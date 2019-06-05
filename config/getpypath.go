package config

import (
	"bytes"
	"log"
	"os/exec"
	"runtime"
	"strings"
)

type pyPath struct{}

func (*pyPath) windows() string {
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

func (*pyPath) others() string {
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

func Get_python_path() string {
	var pyPath pyPath
	switch {
	case runtime.GOOS == "windows":
		return pyPath.windows()
	default:
		return pyPath.others()
	}
}
