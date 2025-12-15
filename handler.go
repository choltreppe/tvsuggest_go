package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	htemplate "html/template"
	"log"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"text/template"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func must[T any](v T, e error) T {
    if e != nil {
        panic(e)
    }
    return v
}

var store = sessions.NewCookieStore(must(os.ReadFile("sessionkey")))

type Handler struct {
    DB *gorm.DB
}

func handleWithUser(handler func(w http.ResponseWriter, r *http.Request, user string)) func(w http.ResponseWriter, r *http.Request) {
    return func(w http.ResponseWriter, r *http.Request) {
        session, err := store.Get(r, "session")
        if err != nil {
            reportServerError(w, err)
        }
        if user, ok := session.Values["user"].(string); ok {
            handler(w, r, user)
        } else {
            http.Redirect(w, r, "/login", 302)
        }
    }
}

func (h *Handler) Routes() http.Handler {
    mux := mux.NewRouter()
    mux.HandleFunc("/", handleWithUser(h.Home))
    mux.HandleFunc("/login", h.Login).Methods("GET", "POST")
    mux.HandleFunc("/signup", h.SignUp).Methods("POST")
    mux.HandleFunc("/signup/confirm/{email}/{code}", h.ConfirmSignUp).Methods("GET")
    mux.HandleFunc("/search/{title}", handleWithUser(h.SearchShow)).Methods("GET")
    mux.HandleFunc("/rate/{id}/{score}", handleWithUser(h.RateShow)).Methods("POST")
    mux.HandleFunc("/my-ratings/{score}", handleWithUser(h.MyRatings)).Methods("GET")
    mux.HandleFunc("/suggestions", handleWithUser(h.Suggestions)).Methods("GET")
    return mux
}

var msgTmpl = must(htemplate.ParseFiles("templates/msg.tmpl"))

func renderMsg(w http.ResponseWriter, title, msg string) {
    type Msg struct {
        Title, Msg string
    }
    msgTmpl.Execute(w, Msg{title, msg})
}

var homeTmpl = must(htemplate.ParseFiles("templates/home.tmpl"))

func (h *Handler) Home(w http.ResponseWriter, r *http.Request, user string) {
    homeTmpl.Execute(w, nil)
}

var loginTmpl = must(htemplate.ParseFiles("templates/login.tmpl"))

func getUserCredentials(w http.ResponseWriter, r *http.Request) (email, password string, ok bool) {
    r.ParseMultipartForm(256)
    emails := r.MultipartForm.Value["email"]
    passwords := r.MultipartForm.Value["passwd"]
    if len(emails) == 1 && len(passwords) == 1 {
        if e, err := mail.ParseAddress(emails[0]); err == nil {
            return e.Address, passwords[0], true
        } else {
            http.Error(w, "Invalid Email Address.", http.StatusBadRequest)
            return
        }
    } else {
        http.Error(w, "Malformed Request.", http.StatusBadRequest)
        return
    }
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodPost:
        if email, password, ok := getUserCredentials(w, r); ok && VerifyUser(h.DB, email, password) {
            session, _ := store.Get(r, "session")
            session.Values["user"] = email
            session.Save(r, w)
            w.WriteHeader(http.StatusOK)
        } else {
            http.Error(w, "Incorrect credentials. Either the email or the password is wrong.", http.StatusBadRequest)
        }
    case http.MethodGet:
        loginTmpl.Execute(w, nil)
    default:
        http.NotFound(w, r)
    }
}

func generateRandomCode(length int) (string, error) {
    b := make([]byte, length)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    code := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
    if len(code) > length {
        code = code[:length]
    }
    return code, nil
}

const senderEmailAddress = "noreply@tvsuggest.chol.foo"

func sendMail(recipient, subject, msg string) error {
    cmd := exec.Command("/usr/sbin/sendmail", "-t", "-i")
    stdin, err := cmd.StdinPipe()
    if err != nil {
        return err
    }
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Start(); err != nil {
        return err
    }
    fmt.Fprintln(stdin, "From: ", senderEmailAddress)
    fmt.Fprintln(stdin, "To: ", recipient)
    fmt.Fprintln(stdin, "Subject: ", subject)
    fmt.Fprintln(stdin)
    fmt.Fprintln(stdin, msg)
    stdin.Close()
    return cmd.Wait()
}

var signupEmailTmpl = template.Must(template.ParseFiles("templates/signup_email.tmpl"))

func (h *Handler) SignUp(w http.ResponseWriter, r *http.Request) {
    if email, password, ok := getUserCredentials(w, r); ok {
        if len(password) < 5 {
            http.Error(w, "Password too short.", http.StatusBadRequest)
            return
        }
        var userExists bool
        err := h.DB.Model(&User{}).Select("1").Where("email = ?", email).Limit(1).Find(&userExists).Error
        if err != nil {
            reportServerError(w, err)
            return
        }
        if userExists {
            http.Error(w, "A user with this email is already registered.", http.StatusBadRequest)
            return
        }
        hash, err := bcrypt.GenerateFromPassword([]byte(password), 0)
        if err != nil {
            http.Error(w, "Password too long.", http.StatusBadRequest)
            return
        }
        code, err := generateRandomCode(32)
        if err != nil {
            reportServerError(w, err)
            return
        }
        result := h.DB.Create(&User{
            Email: email,
            PwHash: hash,
            ConfirmCode: code,
            IsConfirmed: false,
        })
        if err = result.Error; err != nil {
            reportServerError(w, err)
            return
        }
        var buf bytes.Buffer
        type confirmInfo struct { Email, Code string }
        signupEmailTmpl.Execute(&buf, confirmInfo{email, url.QueryEscape(code)})
        if err = sendMail(email, "TV-Suggest Registration", buf.String()); err != nil {
            reportServerError(w, err)
            return
        }
        w.WriteHeader(http.StatusOK)
    }
}

func (h *Handler) ConfirmSignUp(w http.ResponseWriter, r *http.Request) {
    pathParams := mux.Vars(r)
    email, code := pathParams["email"], pathParams["code"]
    var user User
    err := h.DB.Where("email = ?", email).Find(&user).Error
    if err != nil {
        log.Println(err)
        renderMsg(w, "Error", "There was an error. Maybe the registration request expired. Please try to sign up again.")
        return
    }
    if user.ConfirmCode != code {
        renderMsg(w, "Wrong Code", "The confirmation code is incorrect.")
    } else {
        user.IsConfirmed = true
        h.DB.Save(&user)
        renderMsg(w, "Registration Completed", "You are now registered and can log in.")
    }
}


func reportServerError(w http.ResponseWriter, err error) {
    log.Println(err)
    http.Error(w, "Sorry, something went wrong.", http.StatusInternalServerError)
}


var showTmpl = must(htemplate.ParseFiles("templates/show.tmpl"))

func renderShow(w http.ResponseWriter, show Show, rating int8) {
    type RatingButton struct {
        Name string
        Score int8
        Selected bool
    }
    type ShowExt struct {
        Show
        RatingButtons [4]RatingButton
    }
    rb := func(name string, score int8) RatingButton {
        return RatingButton{name, score, score == rating}
    }
    showTmpl.Execute(w, ShowExt{
        Show: show,
        RatingButtons: [4]RatingButton{
            rb("worse" , -2),
            rb("bad"   , -1),
            rb("good"  ,  1),
            rb("better",  2),
        },
    })
}

func (h *Handler) SearchShow(w http.ResponseWriter, r *http.Request, user string) {
    shows, err := FindShows(mux.Vars(r)["title"])
    if err != nil {
        reportServerError(w, err)
        return
    }
    for _, show := range shows {
        renderShow(w, show, GetShowRating(h.DB, user, show.ID))
    }
}

func (h *Handler) RateShow(w http.ResponseWriter, r *http.Request, user string) {
    pathVars := mux.Vars(r)
    score, err := strconv.ParseInt(pathVars["score"], 10, 8)
    if err != nil {
        http.Error(w, "Invalid rating.", http.StatusBadRequest)
        return
    }
    err = SetShowRating(h.DB, user, pathVars["id"], int8(score))
    if err != nil {
        reportServerError(w, err)
        return
    }
}

func (h *Handler) MyRatings(w http.ResponseWriter, r *http.Request, user string) {
    scoreBig, err := strconv.ParseInt(mux.Vars(r)["score"], 10, 8)
    if err != nil {
        http.Error(w, "Invalid rating.", http.StatusBadRequest)
        return
    }
    score := int8(scoreBig)
    shows, err := ShowsWithRating(h.DB, user, score)
    if err != nil {
        reportServerError(w, err)
        return
    }
    for _, show := range shows {
        renderShow(w, show, score)
    }
}

func (h *Handler) Suggestions(w http.ResponseWriter, r *http.Request, user string) {
    shows, err := SuggestedShows(h.DB, user)
    if err != nil {
        reportServerError(w, err)
        return
    }
    for _, show := range shows {
        renderShow(w, show, 0)
    }
}