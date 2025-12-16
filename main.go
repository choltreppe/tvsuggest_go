package main

import (
  "net/http"
)

func main() {
  h := newHandler()
  http.Handle("/", h.Routes())
  http.Handle("/static/", http.FileServer(http.Dir(".")))
  http.ListenAndServe(":8090", nil)
}