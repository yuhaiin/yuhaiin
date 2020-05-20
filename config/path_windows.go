// +build windows

package config

import (
	"bytes"
	"log"
	"os/exec"
	"os/user"
	"strings"
)

var (
	usr, _ = user.Current()
	Path   = usr.HomeDir + pathSeparator + "AppData" + pathSeparator + "Roaming" + pathSeparator + "yuhaiin"
)

// GetPythonPath get python path
func GetPythonPath() string {
	var out bytes.Buffer
	cmd := exec.Command("cmd", "/c", "where python")
	cmd.Stdin = strings.NewReader("some input")
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
		return ""
	}
	return strings.Replace(out.String(), "\r\n", "", -1)
}
