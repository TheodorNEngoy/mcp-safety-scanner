package main

import (
	"io"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
	w.WriteHeader(200)
}

