//go:build linux

package device

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNewFdBorrowsCallerDescriptor(t *testing.T) {
	t.Run("caller may close before native reader", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil { t.Fatal(err) }
		defer writer.Close()
		dev, err := NewFd(int(reader.Fd()), 1500)
		if err != nil { t.Fatal(err) }
		defer dev.Close()
		if err := reader.Close(); err != nil { t.Fatal(err) }
		payload := []byte("borrowed-fd")
		if _, err := writer.Write(payload); err != nil { t.Fatal(err) }
		buffer := make([]byte, 128)
		sizes := []int{0}
		n, err := dev.Read([][]byte{buffer}, sizes)
		if err != nil || n != 1 || sizes[0] != len(payload) || string(buffer[:sizes[0]]) != string(payload) {
			t.Fatalf("read after original close: n=%d size=%d err=%v data=%q", n, sizes[0], err, buffer[:max(sizes[0],0)])
		}
	})
	t.Run("native may close without closing original", func(t *testing.T) {
		reader, writer, err := os.Pipe()
		if err != nil { t.Fatal(err) }
		defer reader.Close()
		defer writer.Close()
		dev, err := NewFd(int(reader.Fd()), 1500)
		if err != nil { t.Fatal(err) }
		if err := dev.Close(); err != nil { t.Fatal(err) }
		if _, err := writer.Write([]byte{'a'}); err != nil { t.Fatal(err) }
		b := make([]byte, 1)
		if _, err := reader.Read(b); err != nil || b[0] != 'a' {
			t.Fatalf("original closed by native device: data=%q err=%v", b, err)
		}
	})
}

func TestBorrowedFDDuplicationIsCloexecAndRejectsClosedFD(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil { t.Fatal(err) }
	defer reader.Close()
	defer writer.Close()
	owned, err := DuplicateBorrowedFD(int(reader.Fd()))
	if err != nil { t.Fatal(err) }
	defer unix.Close(owned)
	if owned == int(reader.Fd()) { t.Fatal("borrowed FD reused without duplication") }
	flags, err := unix.FcntlInt(uintptr(owned), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("duplicate missing FD_CLOEXEC: flags=%x err=%v", flags, err)
	}
	if _, err := NewFd(-1, 1500); !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalid borrowed FD error = %v, want EBADF", err)
	}
}
