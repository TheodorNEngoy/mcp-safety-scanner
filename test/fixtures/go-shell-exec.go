package main

import "os/exec"

func bad(userInput string) error {
	// This should be flagged.
	cmd := exec.Command("sh", "-c", userInput)
	return cmd.Run()
}

