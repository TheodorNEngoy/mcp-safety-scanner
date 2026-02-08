package main

import "net/http"

func main() {
	// Loopback bind: should NOT be flagged.
	_ = http.ListenAndServe("localhost:8080", nil)
}

