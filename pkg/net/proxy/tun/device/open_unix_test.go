//go:build unix && !aix && !ppc64 && !linux

package device

import (
	"errors"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"golang.org/x/sys/unix"
)

func TestOpenWriterFailedInspectLeavesBorrowedFDOpen(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(reader.Fd())

	dev, err := OpenWriter(netlink.TunScheme{Scheme: "fd", Fd: fd}, 1500)
	if err == nil {
		dev.Close()
		t.Fatal("pipe must be rejected as a TUN device")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("failed TUN inspection closed caller fd: %v", err)
	}
	if _, err := writer.Write([]byte{'a'}); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := reader.Read(buffer); err != nil || buffer[0] != 'a' {
		t.Fatalf("borrowed fd unusable after TUN rejection: data=%q err=%v", buffer, err)
	}
}

func TestOpenWriterRejectsInvalidBorrowedFD(t *testing.T) {
	_, err := OpenWriter(netlink.TunScheme{Scheme: "fd", Fd: -1}, 1500)
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalid borrowed FD error = %v, want EBADF", err)
	}
}
