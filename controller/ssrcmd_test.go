package controller

import (
	"os/exec"
	"testing"
	"time"
)

func TestGetFreePort(t *testing.T) {
	t.Log(GetFreePort())
}

func TestCmd(t *testing.T) {
	cmd := append([]string{}, "ls", "-a")
	x := exec.Command(cmd[0], cmd[1:]...)
	if err := x.Start(); err != nil {
		t.Error(err)
	}
	if err := x.Wait(); err != nil {
		t.Error(err)
	}
}

func TestLongCmd(t *testing.T) {
	cmd := append([]string{}, "python", "-m", "http.server")
	x := exec.Command(cmd[0], cmd[1:]...)
	if err := x.Start(); err != nil {
		t.Error(err)
		return
	}
	go func() {
		if err := x.Wait(); err != nil {
			t.Error(err)
		}
	}()
	time.Sleep(2 * time.Second)
	if x.Process != nil {
		x.Process.Kill()
	}
}
