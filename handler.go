package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Handler struct {
    DB *gorm.DB
}

var store = sessions.NewCookieStore([]byte("hDIs723jH(g&d$cdl37lo90)"))

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
    mux.HandleFunc("/login", h.Login)
    mux.HandleFunc("/register", h.RegisterUser).Methods("POST")
    mux.HandleFunc("/search/{title}", handleWithUser(h.SearchShow)).Methods("GET")
    mux.HandleFunc("/rate/{id}/{score}", handleWithUser(h.RateShow)).Methods("POST")
    mux.HandleFunc("/my-ratings/{score}", handleWithUser(h.MyRatings)).Methods("GET")
    mux.HandleFunc("/suggestions", handleWithUser(h.Suggestions)).Methods("GET")
    return mux
}

func loadTemplate(tmpl ...string) *template.Template {
    return template.Must(template.ParseFiles(tmpl...))
}

var homeTmpl = loadTemplate("templates/home.tmpl")

func (h *Handler) Home(w http.ResponseWriter, r *http.Request, user string) {
    homeTmpl.Execute(w, nil)
}

var loginTmpl = loadTemplate("templates/login.tmpl")

func getUserCredentials(w http.ResponseWriter, r *http.Request) (email, password string, ok bool) {
    r.ParseMultipartForm(256)
    emails := r.MultipartForm.Value["email"]
    passwords := r.MultipartForm.Value["passwd"]
    if len(emails) == 1 && len(passwords) == 1 {
        return emails[0], passwords[0], true
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

func (h *Handler) RegisterUser(w http.ResponseWriter, r *http.Request) {
    if email, password, ok := getUserCredentials(w, r); ok {
        var userExists bool
        err := h.DB.Model(&User{}).Select("1").Where("email = ?", email).Limit(1).Find(&userExists).Error
        if err != nil {
            reportServerError(w, err)
        } else if userExists {
            http.Error(w, "A user with this email is already registered.", http.StatusBadRequest)
        } else if hash, err := bcrypt.GenerateFromPassword([]byte(password), 0); err == nil {
            result := h.DB.Create(&User{Email: email, PwHash: hash})
            if result.Error != nil {
                w.WriteHeader(http.StatusOK)
            } else {
                reportServerError(w, err)
            }
        } else {
            http.Error(w, "Password too long.", http.StatusBadRequest)
        }
    }
}


func reportServerError(w http.ResponseWriter, err error) {
    fmt.Println(err)
    http.Error(w, "Sorry, something went wrong.", http.StatusInternalServerError)
}


var showTmpl = loadTemplate("templates/show.tmpl")

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