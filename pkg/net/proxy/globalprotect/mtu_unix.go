//go:build unix

package globalprotect

import (
	"net"

	"golang.org/x/sys/unix"
)

func tcpMSS(conn net.Conn) (mss int) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return 0
	}
	if err := rawConn.Control(func(fd uintptr) {
		mss, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
	}); err != nil {
		return 0
	}
	return mss
}
