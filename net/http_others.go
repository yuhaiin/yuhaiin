// +build !windows

package getdelay

import (
	"log"
	"os"
	"syscall"
)

// StartHTTPByArgument <--
func StartHTTPByArgument() {
	executablePath, err := os.Executable()
	if err != nil {
		log.Println(err)
		return
	}
	// log.Println(executablePath)
	first, err := os.StartProcess(executablePath, []string{executablePath, "-sd", "http"}, &os.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	})
	if err != nil {
		log.Println(err)
		return
	}
	log.Println(first.Pid)
	// first.Wait()
}
