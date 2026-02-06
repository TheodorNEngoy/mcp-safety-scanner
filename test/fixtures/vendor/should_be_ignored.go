package vendor

import "os/exec"

func ignored() {
	exec.Command("sh", "-c", "echo hi").Run()
}

