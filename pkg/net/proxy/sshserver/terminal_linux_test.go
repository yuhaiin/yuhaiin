//go:build linux && !android

package sshserver

import (
	"strings"
	"testing"

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
