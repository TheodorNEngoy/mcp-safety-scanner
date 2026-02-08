package main

import "net/http"

func main() {
	// Public bind via empty host: should be flagged.
	_ = http.ListenAndServe(":8080", nil)
}

