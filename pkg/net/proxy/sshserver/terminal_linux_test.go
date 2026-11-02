//go:build linux && !android

package sshserver

import (
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestSSHServerPTYTerminal(t *testing.T) {
	requireSSHSessionIntegration(t)
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	for _, tc := range []struct{ terminal, colors string }{
		{"xterm", "8"},
		{"xterm-256color", "256"},
	} {
		t.Run(tc.terminal, func(t *testing.T) {
			session, err := client.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if err := session.RequestPty(tc.terminal, 24, 80, gossh.TerminalModes{}); err != nil {
				t.Fatal(err)
			}
			output, err := session.CombinedOutput("printf 'TERM=%s\\n' \"$TERM\"; tput colors")
			if err != nil {
				t.Fatalf("terminal probe: %v\n%s", err, output)
			}
			got := strings.ReplaceAll(string(output), "\r\n", "\n")
			want := "TERM=" + tc.terminal + "\n" + tc.colors + "\n"
			if got != want {
				t.Fatalf("terminal capabilities: got %q, want %q", got, want)
			}
		})
	}
}

func TestSSHServerRejectsInvalidPTYTerminal(t *testing.T) {
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	for _, terminal := range []string{strings.Repeat("x", 129), "xterm\x00", "xterm\n", "xterm\r"} {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if err := session.RequestPty(terminal, 24, 80, gossh.TerminalModes{}); err == nil {
			t.Errorf("accepted invalid terminal name %q", terminal)
		}
		if err := session.RequestPty("xterm-256color", 24, 80, gossh.TerminalModes{}); err != nil {
			t.Errorf("valid PTY request rejected after invalid request: %v", err)
		}
		_ = session.Close()
	}
}

func TestSSHServerExecDoesNotInventTerminal(t *testing.T) {
	requireSSHSessionIntegration(t)
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	output := runSSHCommand(t, client, "env")
	for line := range strings.SplitSeq(string(output), "\n") {
		if strings.HasPrefix(line, "TERM=") {
			t.Fatalf("non-PTY exec advertised terminal capabilities: %s", line)
		}
	}
}

func TestSSHServerPTYDrainsOutputBeforeExit(t *testing.T) {
	requireSSHSessionIntegration(t)
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	output, err := session.Output("seq 1 50000")
	if err != nil {
		t.Fatalf("seq: %v", err)
	}
	if got := strings.TrimSpace(string(output)); !strings.HasSuffix(got, "\n50000") {
		t.Fatalf("PTY output truncated: %d bytes, tail %q", len(output), got[max(0, len(got)-32):])
	}
}

func TestSSHServerExecExitsWithStdinOpen(t *testing.T) {
	requireSSHSessionIntegration(t)
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	// Like an interactive OpenSSH client, never send EOF on stdin.
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	done := make(chan error, 1)
	go func() { done <- session.Run("true") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exec with open stdin: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("exec did not complete while client stdin was open")
	}
}
