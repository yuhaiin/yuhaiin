package helper

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID returns the user id of the peer (SO_PEERCRED). The service only
// runs on macOS; this lets its tests run on Linux.
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
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
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
