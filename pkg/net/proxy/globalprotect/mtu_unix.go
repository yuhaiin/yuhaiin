//go:build unix

package globalprotect

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func tcpMSS(conn net.Conn) (mss int) {
	// syscall.Conn, not *net.TCPConn: dialer wrappers embed the TCP socket.
	if _, ok := conn.LocalAddr().(*net.TCPAddr); !ok {
		return 0
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0
	}
	rawConn, err := sc.SyscallConn()
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
