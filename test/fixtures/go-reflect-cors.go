package main

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {
	// This should be flagged.
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
}

