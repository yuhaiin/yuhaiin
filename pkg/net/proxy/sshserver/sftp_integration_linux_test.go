//go:build linux && !android

package sshserver

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) {
	// Re-exec the actual embedded server when Session.Spawn launches this
	// test binary, matching cmd/yuhaiin's internal-sftp dispatch.
	if len(os.Args) > 1 && os.Args[1] == "internal-sftp" {
		if err := RunSFTP(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func requireSSHSessionIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(sshIntegrationEnv) != "1" && os.Getenv("YUH_SSH_SERVER_NAMESPACE_TEST") != "1" {
		t.Skip("requires Linux TUN and namespace privileges; set YUH_SSH_SERVER_INTEGRATION=1")
	}
}

func TestSSHServerSFTPIntegration(t *testing.T) {
	requireSSHSessionIntegration(t)
	root, err := os.MkdirTemp("/tmp", "yuhaiin-sftp-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	ro := filepath.Join(root, "protected")
	if err := os.Mkdir(ro, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ro, 0o777); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(ro, "data")
	if err := os.WriteFile(protected, []byte("protected"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(protected, 0o666); err != nil {
		t.Fatal(err)
	}
	config, signer := newSSHServerTestIdentity(t)
	config.SFTPReadOnlyPaths = []string{ro}
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	ssh := dialSSHServer(t, server, config.Username, signer)
	for range 2 {
		client, err := sftp.NewClient(ssh)
		if err != nil {
			t.Fatal(err)
		}
		file, err := client.Create(filepath.Join(root, "upload"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("round trip")); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		file, err = client.Open(filepath.Join(root, "upload"))
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(file)
		_ = file.Close()
		if err != nil || string(data) != "round trip" {
			t.Fatalf("download: %q, %v", data, err)
		}
		f, err := client.Create(protected)
		if f != nil {
			_ = f.Close()
		}
		requireSFTPPermission(t, err)
		// The policy belongs to SFTP. Shell commands retain ordinary UID/GID
		// access to the exact same file and shared session namespace.
		runSSHCommand(t, ssh, "printf 'shell allowed' > "+sshShellQuote(protected))
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := ssh.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if len(server.slots) != 0 {
		t.Fatal("SFTP leaked a session slot after disconnect")
	}
}

func TestSSHServerUsesSystemHome(t *testing.T) {
	requireSSHSessionIntegration(t)
	account, err := user.LookupId("65534")
	if err != nil {
		t.Skip("system has no UID 65534 account")
	}
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	output := runSSHCommand(t, client, "printf '%s\\n%s\\n%s\\n' \"$HOME\" \"$USER\" \"$SHELL\"; pwd")
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 4 || lines[0] != account.HomeDir || lines[1] != account.Username || lines[2] != config.Shell && lines[2] != "/bin/sh" {
		t.Fatalf("SSH environment did not follow UID %s: %q", strconv.FormatUint(uint64(config.UID), 10), output)
	}
	working := account.HomeDir
	if info, err := os.Stat(working); err != nil || !info.IsDir() {
		working = "/"
	}
	if lines[3] != working {
		t.Fatalf("working directory %q, want %q", lines[3], working)
	}
}

func TestSSHServerRejectsUnknownAndPTYSubsystems(t *testing.T) {
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	client := dialSSHServer(t, server, config.Username, signer)
	for _, name := range []string{"unknown", "sftp"} {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if name == "sftp" {
			if err := session.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
				t.Fatal(err)
			}
		}
		if err := session.RequestSubsystem(name); err == nil {
			t.Errorf("accepted unsupported subsystem %q", name)
		}
		_ = session.Close()
	}
}

func TestSessionUserMatchesSystemAccount(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	home, name := sessionUser(uint32(uid), "arbitrary-ssh-login")
	if home != account.HomeDir || name != account.Username {
		t.Fatalf("got home=%q user=%q, want %q %q", home, name, account.HomeDir, account.Username)
	}
	if home, name := sessionUser(^uint32(0), "numeric-user"); home != "/" || name != "numeric-user" {
		t.Fatalf("unknown UID fallback: %q %q", home, name)
	}
}

func TestSSHServerSFTPDisconnectReleasesSession(t *testing.T) {
	requireSSHSessionIntegration(t)
	config, signer := newSSHServerTestIdentity(t)
	server := startSSHServerTestServer(t, config, newSSHServerTestHandler())
	ssh := dialSSHServer(t, server, config.Username, signer)
	client, err := sftp.NewClient(ssh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Stat("/"); err != nil {
		t.Fatal(err)
	}
	_ = ssh.Close()
	_ = client.Close()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if len(server.slots) != 0 {
		t.Fatal("disconnect leaked a running SFTP command")
	}
}

func BenchmarkSFTPRead(b *testing.B) {
	for _, restricted := range []bool{false, true} {
		name := "SystemPermissions"
		if restricted {
			name = "ReadOnlyPolicy"
		}
		b.Run(name, func(b *testing.B) {
			root := b.TempDir()
			path := filepath.Join(root, "data")
			payload := bytes.Repeat([]byte("x"), 32<<10)
			if err := os.WriteFile(path, payload, 0o644); err != nil {
				b.Fatal(err)
			}
			var paths []string
			if restricted {
				paths = []string{root}
			}
			client := newSFTPTestClient(b, paths)
			file, err := client.Open(path)
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = file.Close() })
			buffer := make([]byte, len(payload))
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := file.ReadAt(buffer, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
