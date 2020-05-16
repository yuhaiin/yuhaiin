// +build !windows

package config

import (
	"bytes"
	"os/exec"
	"os/user"
	"strings"
)

var (
	usr, _ = user.Current()
	Path   = usr.HomeDir + "/.config/yuhaiin"
)

// GetPythonPath get python path
func GetPythonPath() string {
	var out bytes.Buffer
	cmd := exec.Command("sh", "-c", "which python3")
	cmd.Stdin = strings.NewReader("some input")
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		cmd = exec.Command("sh", "-c", "which python")
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			return ""
		}
	}
	return strings.Replace(out.String(), "\n", "", -1)
}
