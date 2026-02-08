package main

import (
	"io"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// Limit the request body size before reading it fully.
	r.Body = http.MaxBytesReader(w, r.Body, 123)
	_, _ = io.ReadAll(r.Body)
	w.WriteHeader(200)
}

