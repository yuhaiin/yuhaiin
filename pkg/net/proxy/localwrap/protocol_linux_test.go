//go:build linux && !android

package localwrap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func socketPair(t testing.TB) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*net.UnixConn, 0, 2)
	for _, fd := range fds {
		file := os.NewFile(uintptr(fd), "test-socket")
		c, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, c.(*net.UnixConn))
		t.Cleanup(func() { _ = c.Close() })
	}
	return connections[0], connections[1]
}

func TestLaunchProtocolPreservesArgumentsAndDescriptors(t *testing.T) {
	a, b := socketPair(t)
	input := request{Version: protocolVersion, Argv: []string{"/bin/echo", "", "a b", "'quoted'", "$(touch forbidden)"}, Env: []string{"VALUE=a=b", "EMPTY="}, Dir: "/tmp"}
	file, err := os.CreateTemp(t.TempDir(), "payload")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("descriptor payload"); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err := sendFiles(a, []*os.File{file}); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(a, input); err != nil {
		t.Fatal(err)
	}
	files, err := receiveFiles(b)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(files)
	var got request
	if err := readFrame(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("got %#v, want %#v", got, input)
	}
	payload, err := io.ReadAll(files[0])
	if err != nil || string(payload) != "descriptor payload" {
		t.Fatalf("descriptor contents: %q %v", payload, err)
	}
	flags, err := unix.FcntlInt(files[0].Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("received FD must be close-on-exec: %d %v", flags, err)
	}
}

func TestDescriptorHandshakeRejectsMissingAndTruncatedRights(t *testing.T) {
	for _, count := range []int{0, 2, 8} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			a, b := socketPair(t)
			file, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			files := make([]*os.File, count)
			for i := range files {
				files[i] = file
			}
			if count == 0 {
				_, err = a.Write([]byte{protocolVersion})
			} else {
				err = sendFiles(a, files)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := receiveFiles(b); err == nil {
				closeFiles(got)
				t.Fatal("invalid rights accepted")
			}
		})
	}
}

func TestReadFrameRejectsOversizeAndTruncation(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxFrame+1)
	var msg message
	if err := readFrame(bytes.NewReader(header[:]), &msg); err == nil {
		t.Fatal("oversized allocation accepted")
	}
	binary.BigEndian.PutUint32(header[:], 100)
	if err := readFrame(bytes.NewReader(header[:]), &msg); !errors.Is(err, io.EOF) {
		t.Fatalf("truncated payload: %v", err)
	}
	if err := readFrame(bytes.NewReader([]byte{0, 0}), &msg); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}

func TestRequestValidation(t *testing.T) {
	valid := request{Version: protocolVersion, Argv: []string{"/bin/true"}, Dir: "/tmp", Env: []string{"KEY=value"}}
	for _, mutate := range []func(*request){func(r *request) { r.Version++ }, func(r *request) { r.Argv = nil }, func(r *request) { r.Argv = []string{"/bin/true", "a\x00b"} }, func(r *request) { r.Dir = "." }, func(r *request) { r.Env = []string{"=value"} }, func(r *request) { r.Env = []string{"KEY=\x00"} }} {
		r := valid
		mutate(&r)
		if err := r.validate(); err == nil {
			t.Fatalf("accepted %#v", r)
		}
	}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkLaunchProtocol(b *testing.B) {
	a, c := socketPair(b)
	file, err := os.Open(os.DevNull)
	if err != nil {
		b.Fatal(err)
	}
	defer file.Close()
	req := request{Version: protocolVersion, Argv: []string{"/usr/bin/curl", "https://example.com"}, Dir: "/tmp", Env: []string{"PATH=/usr/bin:/bin", "HOME=/home/user"}}
	done := make(chan error, 1)
	go func() {
		for {
			files, err := receiveFiles(c)
			if err != nil {
				done <- err
				return
			}
			closeFiles(files)
			var got request
			if err := readFrame(c, &got); err != nil {
				done <- err
				return
			}
			if err := writeFrame(c, message{Exit: new(0)}); err != nil {
				done <- err
				return
			}
		}
	}()
	b.ReportAllocs()
	for b.Loop() {
		if err := sendFiles(a, []*os.File{file, file, file}); err != nil {
			b.Fatal(err)
		}
		if err := writeFrame(a, req); err != nil {
			b.Fatal(err)
		}
		var msg message
		if err := readFrame(a, &msg); err != nil {
			b.Fatal(err)
		}
	}
	_ = a.Close()
	if err := <-done; !errors.Is(err, io.EOF) {
		b.Fatal(err)
	}
}
