package controller

import (
	"bufio"
	"context"
	"os"
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
	x.Stdout = os.Stdout
	x.Stderr = os.Stderr
	if err := x.Start(); err != nil {
		t.Error(err)
	}
	if err := x.Wait(); err != nil {
		t.Error(err)
	}
}

func TestLongCmd(t *testing.T) {
	cmd := append([]string{}, "python", "-m", "http.server")
	ctx, _ := context.WithTimeout(context.Background(), time.Second*2)
	x := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	//x.Stdout = os.Stdout
	x.Stderr = os.Stderr

	stdout, err := x.StdoutPipe()
	if err != nil {
		t.Error(err)
	}
	t.Log(x.Start())
	stdoutReader := bufio.NewReader(stdout)

	go func() {
		for {
			x, err := stdoutReader.ReadString(' ')
			if err != nil {
				t.Error(err)
				break
			}
			t.Log(x)
		}
	}()
	t.Log(x.Wait())
}
