package main

import "net/http"

func main() {
	// Public bind: should be flagged.
	_ = http.ListenAndServe("0.0.0.0:8080", nil)
}

