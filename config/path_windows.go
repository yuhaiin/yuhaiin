// +build windows

package config

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
)

// GetConfigAndSQLPath <-- get the config path
func GetConfigAndSQLPath() (configPath string) {
	return os.Getenv("USERPROFILE") + "\\Documents\\SSRSub"
}

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
