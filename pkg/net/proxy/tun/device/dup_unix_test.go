//go:build linux || (unix && !aix && !ppc64)

package device

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDuplicateTUNFDOwnership(t *testing.T) {
	for _, closeOriginal := range []bool{true, false} {
		name := "close duplicate"
		if closeOriginal {
			name = "close original"
		}
		t.Run(name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			original := int(reader.Fd())
			owned, err := duplicateTUNFD(original)
			if err != nil {
				t.Fatal(err)
			}
			duplicate := os.NewFile(uintptr(owned), "duplicate")
			defer duplicate.Close()
			if owned == original {
				t.Fatal("borrowed FD reused without duplication")
			}
			flags, err := unix.FcntlInt(uintptr(owned), unix.F_GETFD, 0)
			if err != nil || flags&unix.FD_CLOEXEC == 0 {
				t.Fatalf("duplicate missing FD_CLOEXEC: flags=%x err=%v", flags, err)
			}

			closed, remaining := duplicate, reader
			if closeOriginal {
				closed, remaining = reader, duplicate
			}
			if err := closed.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte{'a'}); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 1)
			if _, err := remaining.Read(buffer); err != nil || buffer[0] != 'a' {
				t.Fatalf("closing one descriptor invalidated the other: data=%q err=%v", buffer, err)
			}
		})
	}
}

func TestDuplicateTUNFDRejectsInvalidFD(t *testing.T) {
	if _, err := duplicateTUNFD(-1); !errors.Is(err, unix.EBADF) {
		t.Fatalf("invalid borrowed FD error = %v, want EBADF", err)
	}
}
