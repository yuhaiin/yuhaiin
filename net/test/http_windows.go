// +build windows

package test

import (
	"log"
	"os"
	"os/exec"
)

// StartHTTPByArgument <--
func StartHTTPByArgument() {
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return
	}
	// log.Println(executablePath)

	cmd := exec.Command(executablePath, "-sd", "http")
	cmd.Run()
	log.Println(cmd.Process.Pid)
	// first.Wait()
}

// StartHTTPByArgumentBypass <--
func StartHTTPByArgumentBypass() {
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return
	}
	// log.Println(executablePath)

	cmd := exec.Command(executablePath, "-sd", "httpBp")
	cmd.Run()
	log.Println(cmd.Process.Pid)
	// first.Wait()
}
