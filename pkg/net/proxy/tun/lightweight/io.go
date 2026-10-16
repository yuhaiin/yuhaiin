package lightweight

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// Device operations are packet-atomic. A recoverable write failure accepts no
// packet; a read can return a valid packet together with its next error.
func temporaryPacketError(err error) bool {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) {
		return false
	}
	if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.ENOBUFS) {
		return true
	}
	if e, ok := errors.AsType[interface {
		error
		Temporary() bool
	}](err); ok {
		return e.Temporary()
	}
	return false
}

func (s *Stack) retryPacketIO(err error, attempt int) bool {
	if !temporaryPacketError(err) {
		return false
	}
	if attempt < 4 && errors.Is(err, syscall.EINTR) {
		return !s.closed()
	}
	timer := time.NewTimer(time.Millisecond << min(attempt, 6))
	defer timer.Stop()
	select {
	case <-s.done:
		return false
	case <-timer.C:
		return true
	}
}
