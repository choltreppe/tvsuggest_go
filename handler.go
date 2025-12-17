package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	htemplate "html/template"
	"log"
	"math"
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
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func must[T any](v T, e error) T {
    if e != nil {
        panic(e)
    }
    return v
}

type Handler struct {
    db *gorm.DB
    cookieStore *sessions.CookieStore
}

func newHandler() Handler {
    db, err := gorm.Open(mysql.Open(os.Getenv("DB_DSN")), &gorm.Config{})
    if err != nil {
        panic("Failed to connect database")
    }
    db.AutoMigrate(&User{}, &UserRating{}, /*&ShowRelation{}*/)
    
    return Handler{
        db: db,
        cookieStore: sessions.NewCookieStore([]byte(os.Getenv("COOKIE_SECRET"))),
    }
}

func (h *Handler) Routes() http.Handler {
    mux := mux.NewRouter()

    mux.HandleFunc("/", h.withUser(h.Home))

    mux.HandleFunc("/login", h.Login).Methods("GET", "POST")
    mux.HandleFunc("/signup", h.SignUp).Methods("GET", "POST")
    mux.HandleFunc("/signup/confirm/{email}/{code}", h.ConfirmSignUp).Methods("GET")
    mux.HandleFunc("/pwreset/request", h.RequestPwReset).Methods("GET", "POST")
    mux.HandleFunc("/pwreset/{email}/{code}", h.PwReset).Methods("GET", "POST")

    mux.HandleFunc("/search/{title}", h.withUser(h.SearchShow)).Methods("GET")
    mux.HandleFunc("/rate/{id}/{score}", h.withUser(h.RateShow)).Methods("POST")
    mux.HandleFunc("/my-ratings/{score}", h.withUser(h.MyRatings)).Methods("GET")
    mux.HandleFunc("/suggestions", h.withUser(h.Suggestions)).Methods("GET")

    return mux
}

func (h *Handler) withUser(handler func(w http.ResponseWriter, r *http.Request, user string)) func(http.ResponseWriter, *http.Request) {
    return func(w http.ResponseWriter, r *http.Request) {
        session, err := h.cookieStore.Get(r, "session")
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

func (h *Handler) setUserLoggedIn(w http.ResponseWriter, r *http.Request, email string) {
    session, _ := h.cookieStore.Get(r, "session")
    session.Values["user"] = email
    session.Save(r, w)
}

func reportServerError(w http.ResponseWriter, err error) {
    log.Println(err)
    http.Error(w, "Sorry, something went wrong.", http.StatusInternalServerError)
}

var msgTmpl = must(htemplate.ParseFiles("templates/_base.tmpl", "templates/msg.tmpl"))

func renderMsg(w http.ResponseWriter, title, msg string) {
    type Msg struct {
        Title, Msg string
    }
    msgTmpl.Execute(w, Msg{title, msg})
}

var homeTmpl = must(htemplate.ParseFiles("templates/_base.tmpl", "templates/home.tmpl"))

func (h *Handler) Home(w http.ResponseWriter, r *http.Request, user string) {
    homeTmpl.Execute(w, nil)
}

var loginTmpl = must(htemplate.ParseFiles("templates/_base.tmpl", "templates/login.tmpl"))

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
        if email, password, ok := getUserCredentials(w, r); ok {
            if VerifyUser(h.db, email, password) {
                h.setUserLoggedIn(w, r, email)
                w.WriteHeader(http.StatusOK)
            } else {
                http.Error(w, "Incorrect credentials. Either the email or the password is wrong.", http.StatusBadRequest)
            }
        }
    case http.MethodGet:
        loginTmpl.Execute(w, nil)
    }
}

func generateRandomCode() (string, error) {
    const length = 32
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

const senderEmailAddress = "TV Suggest <noreply@tvsuggest.chol.foo>"

func sendMail(recipient, subject, msg string) error {
    if _, err := os.Stat("/usr/sbin/sendmail"); errors.Is(err, os.ErrNotExist) {
        fmt.Println("To: ", recipient)
        fmt.Println("Subject: ", subject)
        fmt.Println(msg)
        return nil
    
    } else {
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
}

func sendMailWithConfirmLink(recipient, subject string, templ *template.Template, code string) error {
    var buf bytes.Buffer
    type confirmInfo struct { Email, Code string }
    templ.Execute(&buf, confirmInfo{recipient, url.QueryEscape(code)})
    return sendMail(recipient, subject, buf.String())
}

func userExists(db *gorm.DB, email string) (exists bool, err error) {
    err = db.Model(&User{}).Select("1").Where("email = ?", email).Limit(1).Find(&exists).Error
    return
}

var signupTmpl = must(htemplate.ParseFiles("templates/_base.tmpl", "templates/signup.tmpl"))
var signupEmailTmpl = must(template.ParseFiles("templates/emails/confirm_signup.tmpl"))

func (h *Handler) SignUp(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        signupTmpl.Execute(w, nil)

    case http.MethodPost:
        if email, password, ok := getUserCredentials(w, r); ok {
            if len(password) < 5 {
                http.Error(w, "Password too short.", http.StatusBadRequest)
                return
            }
            userExists, err := userExists(h.db, email)
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
            code, err := generateRandomCode()
            if err != nil {
                reportServerError(w, err)
                return
            }
            result := h.db.Create(&User{
                Email: email,
                PwHash: hash,
                ConfirmCode: code,
                IsConfirmed: false,
            })
            if err = result.Error; err != nil {
                reportServerError(w, err)
                return
            }

            if err = sendMailWithConfirmLink(email, "TV-Suggest Registration", signupEmailTmpl, code); err != nil {
                reportServerError(w, err)
                return
            }
            w.WriteHeader(http.StatusOK)
            w.Write([]byte("Registration sent. You should recieve an email with a confirmation link."))
        }
    }
}

func (h *Handler) ConfirmSignUp(w http.ResponseWriter, r *http.Request) {
    pathParams := mux.Vars(r)
    email, code := pathParams["email"], pathParams["code"]
    var user User
    err := h.db.Where("email = ?", email).Find(&user).Error
    if errors.Is(err, gorm.ErrRecordNotFound) {
        renderMsg(w, "Error", "There is no user with this email address.")
    } else if err != nil {
        log.Println(err)
        renderMsg(w, "Wrong Code", "Sorry, something went wrong.")
    } else if user.ConfirmCode != code {
        renderMsg(w, "Wrong Code", "The confirmation code is incorrect.")
    } else {
        user.IsConfirmed = true
        h.db.Save(&user)
        renderMsg(w, "Registration Completed", "You are now registered and can log in.")
    }
}

var pwResetRequestTmpl = must(htemplate.ParseFiles("templates/_base.tmpl", "templates/pwreset_request.tmpl"))
var pwResetMailTmpl = must(template.ParseFiles("templates/emails/pwreset.tmpl"))

func (h *Handler) RequestPwReset(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        pwResetRequestTmpl.Execute(w, nil)

    case http.MethodPost:
        r.ParseMultipartForm(256)
        emails := r.MultipartForm.Value["email"]
        if len(emails) != 1 {
            http.Error(w, "Malformed Request.", http.StatusBadRequest)
            return
        }
        email := emails[0]
        userExists, err := userExists(h.db, email)
        if err != nil {
            reportServerError(w, err)
            return
        }
        if !userExists {
            http.Error(w, "There is no user with this email address.", http.StatusBadRequest)
        } else {
            code, err := generateRandomCode()
            if err != nil {
                reportServerError(w, err)
                return
            }
            err = h.db.Exec("UPDATE users SET confirm_code = ? WHERE email = ?", code, email).Error
            if err != nil {
                reportServerError(w, err)
                return
            }

            if err = sendMailWithConfirmLink(email, "TV-Suggest Password Reset", pwResetMailTmpl, code); err != nil {
                reportServerError(w, err)
                return
            }
            w.WriteHeader(http.StatusOK)
            w.Write([]byte("Reset link sent. You should recieve an email with a link to reset your password."))
        }
    }
}

var pwResetTmpl = must(htemplate.ParseFiles("templates/_base.tmpl", "templates/pwreset.tmpl"))

func (h *Handler) PwReset(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        pwResetTmpl.Execute(w, nil)

    case http.MethodPost:
        pathParams := mux.Vars(r)
        email, code := pathParams["email"], pathParams["code"]

        r.ParseMultipartForm(256)
        passwords := r.MultipartForm.Value["passwd"]
        if len(passwords) != 1 {
            http.Error(w, "Malformed Request.", http.StatusBadRequest)
            return
        }
        password := passwords[0]

        var user User
        err := h.db.Where("email = ?", email).Find(&user).Error
        if errors.Is(err, gorm.ErrRecordNotFound) {
            http.Error(w, "There is no user with this email address.", http.StatusBadRequest)
        } else if err != nil {
            reportServerError(w, err)
        } else if user.ConfirmCode != code {
            http.Error(w, "The confirmation code is incorrect.", http.StatusBadRequest)
        } else if hash, err := bcrypt.GenerateFromPassword([]byte(password), 0); err != nil {
            reportServerError(w, err)
        } else {
            user.PwHash = hash
            h.db.Save(&user)
            h.setUserLoggedIn(w, r, user.Email)
            renderMsg(w, "Registration Completed", "You are now registered and can log in.")
        }   
    }
}


var showTmpl = must(htemplate.ParseFiles("templates/show.tmpl"))

func renderShow(w http.ResponseWriter, show Show, rating *int8) {
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
        selected := false
        if rating != nil {
            selected = score == *rating
        }
        return RatingButton{name, score, selected}
    }
    showTmpl.Execute(w, ShowExt{
        Show: show,
        RatingButtons: [4]RatingButton{
            rb("bad"    , -1),
            rb("neutral",  0),
            rb("good"   ,  1),
            rb("better" ,  2),
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
        renderShow(w, show, GetShowRating(h.db, user, show.ID))
    }
}

func (h *Handler) RateShow(w http.ResponseWriter, r *http.Request, user string) {
    pathVars := mux.Vars(r)
    score, err := strconv.ParseInt(pathVars["score"], 10, 8)
    if err != nil {
        http.Error(w, "Invalid rating.", http.StatusBadRequest)
        return
    }
    err = SetShowRating(h.db, user, pathVars["id"], int8(score))
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
    shows, err := ShowsWithRating(h.db, user, score)
    if err != nil {
        reportServerError(w, err)
        return
    }
    for _, show := range shows {
        renderShow(w, show, &score)
    }
}

func (h *Handler) Suggestions(w http.ResponseWriter, r *http.Request, user string) {
    shows, err := SuggestedShows(h.db, user)
    if err != nil {
        reportServerError(w, err)
        return
    }
    score := int8(math.MinInt8)
    for _, show := range shows {
        renderShow(w, show, &score)
    }
}