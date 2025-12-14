package main

import (
  "net/http"
)

func main() {
  db := InitDB()
  MigrateDB(db)
  h := &Handler{DB: db}
  http.Handle("/", h.Routes())
  http.Handle("/static/", http.FileServer(http.Dir(".")))
  http.ListenAndServe(":8090", nil)
}