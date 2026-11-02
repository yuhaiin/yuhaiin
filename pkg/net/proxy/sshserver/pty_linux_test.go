//go:build linux && !android

package sshserver

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPTYDoesNotBecomeServerControllingTerminal(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// systemd services are session leaders without a controlling terminal.
	// Reproduce that state without changing the test runner's own session.
	command := exec.CommandContext(t.Context(), executable, "-test.run=^TestPTYSessionLeaderHelper$")
	command.Env = append(os.Environ(), "YUH_SSH_PTY_SESSION_LEADER_HELPER=1")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("PTY allocation in session leader: %v\n%s", err, output)
	}
}

func TestPTYSessionLeaderHelper(t *testing.T) {
	if os.Getenv("YUH_SSH_PTY_SESSION_LEADER_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	// Catch an accidental hangup so the helper can report the actual failure.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	defer signal.Stop(signals)
	assertNoControllingTerminal := func() {
		t.Helper()
		fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
			t.Fatal("SSH server acquired a controlling terminal")
		}
		if !errors.Is(err, unix.ENXIO) {
			t.Fatalf("check controlling terminal: %v", err)
		}
	}
	assertNoControllingTerminal()
	pty, err := openPTY(80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer pty.master.Close()
	defer pty.slave.Close()
	assertNoControllingTerminal()

	command := exec.CommandContext(t.Context(), "/bin/true")
	command.Stdin, command.Stdout, command.Stderr = pty.slave, pty.slave, pty.slave
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := command.Run(); err != nil {
		t.Fatalf("child could not acquire its controlling terminal: %v", err)
	}
	assertNoControllingTerminal()
}
