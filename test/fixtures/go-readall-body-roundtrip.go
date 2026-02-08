package main

import (
	"io"
	"net/http"
)

type t struct{}

func (t *t) RoundTrip(req *http.Request) (*http.Response, error) {
	_, _ = io.ReadAll(req.Body)
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

