package main

import "github.com/rs/cors"

func corsHandler() {
	_ = cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	})
}

