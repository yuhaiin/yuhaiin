//go:build linux && !android

package sshserver

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// Exercise the real namespace and packet-stack teardown, including after the
// client disconnects. A blocking duplicated TUN FD can keep Server.Close waiting
// for the stack's read loop even when no SSH client remains connected.
func TestSSHServerCloseActiveSessions(t *testing.T) {
	requireSSHSessionIntegration(t)
	for _, tc := range []struct {
		mode       string
		disconnect bool
	}{
		{"exec", false},
		{"pty", false},
		{"sftp", false},
		{"exec", true},
		{"pty", true},
		{"sftp", true},
	} {
		t.Run(fmt.Sprintf("%s/disconnect=%t", tc.mode, tc.disconnect), func(t *testing.T) {
			config, signer := newSSHServerTestIdentity(t)
			server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
			client := dialSSHServer(t, server, config.Username, signer)
			if tc.mode == "sftp" {
				sftpClient, err := sftp.NewClient(client)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = sftpClient.Close() })
			} else {
				session, err := client.NewSession()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = session.Close() })
				if tc.mode == "pty" {
					if err := session.RequestPty("xterm", 24, 80, nil); err != nil {
						t.Fatal(err)
					}
				}
				stdout, err := session.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				// Keep the command blocked on stdin until shutdown cancels it.
				// A nil stdin would send EOF as soon as Start returns.
				stdin, err := session.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = stdin.Close() })
				if err := session.Start("printf 'ready\\n'; read -r finish"); err != nil {
					t.Fatal(err)
				}
				if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || (line != "ready\n" && line != "ready\r\n") {
					t.Fatalf("command readiness: %q, %v", line, err)
				}
			}
			if tc.disconnect {
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			}

			closed := make(chan error, 1)
			go func() { closed <- server.Close() }()
			select {
			case err := <-closed:
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				stacks := make([]byte, 1<<20)
				n := runtime.Stack(stacks, true)
				t.Fatalf("server shutdown blocked with an active %s session\n%s", tc.mode, stacks[:n])
			}
			if len(server.slots) != 0 {
				t.Fatal("shutdown left an active session")
			}
		})
	}
}
