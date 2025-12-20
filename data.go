package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type IntString string

func (s *IntString) UnmarshalJSON(b []byte) error {
    if string(b) == "null" {
        *s = ""
        return nil
    }
    var num json.Number
    if err := json.Unmarshal(b, &num); err != nil {
        return err
    }
    *s = IntString(num.String())
    return nil
}

type User struct {
    Email string `gorm:"primaryKey"`
    PwHash []byte
    Ratings []UserRating `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`

    ConfirmCode string
    IsConfirmed bool
}

type UserRating struct {
    UserEmail, ShowId string `gorm:"primaryKey"`
    Score int8 `gorm:"check: score >= -1 AND score <= 2"`
    UpdatedAt time.Time
}

// maybe precompute relations periodically in future if data gets bigger
/*type ShowRelation struct {
    Show1, Show2 string `gorm:"primaryKey"`
    Score int
}*/

type Show struct {
    ID string `json:"id"`
    Type string `json:"type"`
    Title string `json:"primaryTitle"`
    Img struct {
        Url string `json:"url"`
    } `json:"primaryImage"`
    StartYear IntString `json:"startYear"`
}


func VerifyUser(db *gorm.DB, email, password string) bool {
    var user User
    err := db.Where("email = ? AND is_confirmed", email).First(&user).Error
    return err == nil && bcrypt.CompareHashAndPassword(user.PwHash, []byte(password)) == nil
}


const movieDbApiUrl = "https://api.imdbapi.dev"

func FindShows(title string) (shows []Show, err error) {
    queryVars := url.Values{}
    queryVars.Set("query", title)
    queryVars.Set("limit", "42")
    resp, err := http.Get(movieDbApiUrl + "/search/titles?" + queryVars.Encode())
    if err != nil { return }
    body, err := io.ReadAll(resp.Body)
    resp.Body.Close()
    if err != nil { return }
    if resp.StatusCode != http.StatusOK {
        return nil, errors.New(string(body))
    }
    type ShowList struct {
        Titles []Show `json:"titles"`
    }
    var showList ShowList
    if err = json.Unmarshal(body, &showList); err != nil { return }
    return showList.Titles, nil
}

func GetShowRating(db *gorm.DB, user, showId string) *int8 {
    var score int8
    err := db.Model(&UserRating{}).
        Order("updated_at desc").
        Select("score").
        Where("user_email = ? AND show_id = ?", user, showId).
        First(&score).Error
    if errors.Is(err, gorm.ErrRecordNotFound) {
        return nil
    }
    return &score
}

func SetShowRating(db *gorm.DB, user, showId string, score int8) error {
    rating := UserRating{
        UserEmail: user,
        ShowId: showId,
        Score: score,
    }
    return db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&rating).Error
}

func getShow(id string) (show Show, err error) {
    resp, err := http.Get(movieDbApiUrl + "/titles/" + id)
    if err != nil { return }
    body, err := io.ReadAll(resp.Body)
    resp.Body.Close()
    if err != nil { return }
    if err = json.Unmarshal(body, &show); err != nil { return }
    return
}

func ShowsWithRating(db *gorm.DB, user string, score int8) (shows []Show, err error) {
    rows, err := db.Raw("SELECT show_id FROM user_ratings WHERE user_email = ? AND score = ?", user, score).Rows()

    if err != nil { return }
    
    shows = []Show{}
    for rows.Next() {
        var id string
        rows.Scan(&id)
        show, err := getShow(id)
        if err != nil { return nil, err}
        shows = append(shows, show)
    }
    return
}

func SuggestedShows(db *gorm.DB, user string) (shows []Show, err error) {
    rows, err := db.Raw(`
        WITH own_ratings AS (
            SELECT show_id, score
            FROM user_ratings
            WHERE user_email = ? AND score > 0
        ),
        subj_ratings AS (
            SELECT user_ratings.show_id, (own_ratings.score * sum(user_ratings.score)) AS score
            FROM user_ratings
            INNER JOIN own_ratings
            WHERE user_ratings.show_id NOT IN (SELECT show_id FROM own_ratings)
            GROUP BY user_ratings.show_id
        )
        SELECT show_id
        FROM subj_ratings
        WHERE score > 0
        ORDER BY score
        LIMIT 40
    `, user).Rows()

    if err != nil { return }
    
    shows = []Show{}
    for rows.Next() {
        var id string
        rows.Scan(&id)
        show, err := getShow(id)
        if err != nil { return nil, err}
        shows = append(shows, show)
    }
    return
}