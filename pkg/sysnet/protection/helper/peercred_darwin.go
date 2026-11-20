package helper

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID returns the effective user id of the process on the other end of
// a Unix socket (LOCAL_PEERCRED), which the kernel fills in and the client
// cannot forge.
func PeerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			sockErr = err
			return
		}
		uid = int(cred.Uid)
	}); err != nil {
		return -1, err
	}
	return uid, sockErr
}
