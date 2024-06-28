package relay

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestErrIs(t *testing.T) {
	reset := &os.SyscallError{
		Err:     syscall.ECONNRESET,
		Syscall: "connect",
	}

	if !errors.Is(reset, syscall.ECONNRESET) {
		t.Fatal("not equal")
	}

	t.Log(reset)
}
