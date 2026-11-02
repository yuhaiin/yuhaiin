//go:build linux && !android

package sshserver

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

func newSFTPTestClient(tb testing.TB, paths []string) *sftp.Client {
	tb.Helper()
	server, remote := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- serveSFTP(server, paths)
		_ = server.Close()
	}()
	client, err := sftp.NewClientPipe(remote, remote)
	if err != nil {
		_ = remote.Close()
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		_ = client.Close()
		_ = remote.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
				tb.Errorf("SFTP shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			_ = server.Close()
			tb.Error("SFTP did not release its open handles after disconnect")
		}
	})
	return client
}

func requireSFTPPermission(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, os.ErrPermission) {
		return
	}
	status, ok := errors.AsType[*sftp.StatusError](err)
	if !ok || status.Code != 3 {
		t.Fatalf("wanted SFTP permission denied, got %v", err)
	}
}

func TestSFTPReadOnlyDirectories(t *testing.T) {
	root := t.TempDir()
	ro := filepath.Join(root, "protected")
	if err := os.MkdirAll(filepath.Join(ro, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(ro, "data")
	if err := os.WriteFile(file, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(root, "protected-sibling")
	if err := os.Mkdir(writable, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(writable, "data")
	if err := os.WriteFile(out, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	client := newSFTPTestClient(t, []string{ro})
	for name, operation := range map[string]func() error{
		"upload": func() error {
			f, err := client.Create(file)
			if f != nil {
				_ = f.Close()
			}
			return err
		},
		"create": func() error {
			f, err := client.Create(filepath.Join(ro, "new"))
			if f != nil {
				_ = f.Close()
			}
			return err
		},
		"append": func() error {
			f, err := client.OpenFile(file, os.O_WRONLY|os.O_APPEND)
			if f != nil {
				_ = f.Close()
			}
			return err
		},
		"remove":           func() error { return client.Remove(file) },
		"rmdir":            func() error { return client.RemoveDirectory(filepath.Join(ro, "empty")) },
		"mkdir":            func() error { return client.Mkdir(filepath.Join(ro, "new-directory")) },
		"chmod":            func() error { return client.Chmod(file, 0o600) },
		"chown":            func() error { return client.Chown(file, os.Getuid(), os.Getgid()) },
		"times":            func() error { return client.Chtimes(file, time.Now(), time.Now()) },
		"truncate":         func() error { return client.Truncate(file, 0) },
		"rename out":       func() error { return client.Rename(file, filepath.Join(writable, "moved")) },
		"rename in":        func() error { return client.Rename(out, filepath.Join(ro, "moved")) },
		"rename ancestor":  func() error { return client.Rename(root, root+"-moved") },
		"posix rename out": func() error { return client.PosixRename(file, out) },
		"posix rename in":  func() error { return client.PosixRename(out, file) },
		"hardlink out":     func() error { return client.Link(file, filepath.Join(writable, "hardlink")) },
		"hardlink in":      func() error { return client.Link(out, filepath.Join(ro, "hardlink")) },
		"symlink in":       func() error { return client.Symlink(out, filepath.Join(ro, "symlink")) },
	} {
		t.Run(name, func(t *testing.T) { requireSFTPPermission(t, operation()) })
	}
	reader, err := client.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(data) != "original" {
		t.Fatalf("read-only data changed or became unreadable: %q, %v", data, err)
	}
	if _, err := client.ReadDir(ro); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Stat(file); err != nil {
		t.Fatal(err)
	}
	if f, err := client.Create(filepath.Join(writable, "new")); err != nil {
		t.Fatal("prefix sibling was incorrectly restricted:", err)
	} else {
		_ = f.Close()
	}
}

func TestSFTPReadOnlySymlinks(t *testing.T) {
	root := t.TempDir()
	ro := filepath.Join(root, "protected")
	if err := os.Mkdir(ro, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(ro, "data")
	if err := os.WriteFile(file, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(ro, alias); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(ro, "new"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{ro, alias} {
		t.Run(filepath.Base(rule), func(t *testing.T) {
			client := newSFTPTestClient(t, []string{rule})
			for _, path := range []string{file, filepath.Join(alias, "data"), filepath.Join(alias, "new"), dangling} {
				f, err := client.Create(path)
				if f != nil {
					_ = f.Close()
				}
				requireSFTPPermission(t, err)
			}
			if target, err := client.ReadLink(alias); err != nil || target != ro {
				t.Fatalf("readlink: %q, %v", target, err)
			}
			if info, err := client.Lstat(alias); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("lstat: %v, %v", info, err)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(ro, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created through protected symlink: %v", err)
	}
}

func TestSFTPWritesFollowSystemPermissions(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		name := "default"
		if restricted {
			name = "unlisted paths"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			var paths []string
			if restricted {
				paths = []string{filepath.Join(root, "protected")}
			}
			client := newSFTPTestClient(t, paths)
			file := filepath.Join(root, "data")
			f, err := client.Create(file)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			f, err = client.OpenFile(file, os.O_RDWR|os.O_APPEND)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt([]byte(" world"), 5); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
			data, err := os.ReadFile(file)
			if err != nil || string(data) != "hello world" {
				t.Fatalf("append: %q, %v", data, err)
			}
			if err := client.Truncate(file, 5); err != nil {
				t.Fatal(err)
			}
			if err := client.Chmod(file, 0o400); err != nil {
				t.Fatal(err)
			}
			if os.Geteuid() != 0 {
				f, err := client.Create(file)
				if f != nil {
					_ = f.Close()
				}
				requireSFTPPermission(t, err)
			}
			if err := client.Chmod(file, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := client.Chtimes(file, time.Now(), time.Now()); err != nil {
				t.Fatal(err)
			}
			moved := file + "-moved"
			if err := client.Rename(file, moved); err != nil {
				t.Fatal(err)
			}
			if err := client.Link(moved, file); err != nil {
				t.Fatal(err)
			}
			if err := client.PosixRename(moved, file); err != nil {
				t.Fatal(err)
			}
			if err := client.Remove(file); err != nil {
				t.Fatal(err)
			}
			wd, err := client.Getwd()
			want, _ := os.Getwd()
			if err != nil || wd != want {
				t.Fatalf("SFTP home: %q, want %q: %v", wd, want, err)
			}
		})
	}
}

func TestSFTPOpenHandleCannotWriteAfterMoveIntoReadOnlyDirectory(t *testing.T) {
	root := t.TempDir()
	ro := filepath.Join(root, "protected")
	if err := os.Mkdir(ro, 0o755); err != nil {
		t.Fatal(err)
	}
	client := newSFTPTestClient(t, []string{ro})
	source := filepath.Join(root, "data")
	file, err := client.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// Simulate an external process moving a file that SFTP already opened.
	if err := os.Rename(source, filepath.Join(ro, "data")); err != nil {
		t.Fatal(err)
	}
	_, err = file.Write([]byte("must not be written"))
	requireSFTPPermission(t, err)
}

func BenchmarkSFTPTransfer(b *testing.B) {
	for _, restricted := range []bool{false, true} {
		name := "SystemPermissions"
		if restricted {
			name = "ReadOnlyPolicy"
		}
		b.Run(name, func(b *testing.B) {
			root := b.TempDir()
			var paths []string
			if restricted {
				paths = []string{filepath.Join(root, "protected")}
			}
			client := newSFTPTestClient(b, paths)
			file, err := client.Create(filepath.Join(root, "data"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = file.Close() })
			payload := bytes.Repeat([]byte("x"), 32<<10)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := file.WriteAt(payload, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
