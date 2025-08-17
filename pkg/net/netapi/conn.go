package netapi

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"
)

type LogConn struct {
	net.Conn
}

func (l *LogConn) Write(b []byte) (int, error) {
	return l.Conn.Write(b)
}

func (l *LogConn) Read(b []byte) (int, error) {
	n, err := l.Conn.Read(b)
	if err != nil {
		fmt.Println("tls read failed", "err", err)
	}

	return n, err
}

func (l *LogConn) SetDeadline(t time.Time) error {
	_, file, line, _ := runtime.Caller(3)
	fmt.Println("set deadline", "time", t, "line", line, "file", file, "time", t)

	return l.Conn.SetDeadline(t)
}

func (l *LogConn) SetReadDeadline(t time.Time) error {
	_, file, line, _ := runtime.Caller(3)
	fmt.Println("set read deadline", "time", t, "line", line, "file", file, "time", t)

	return l.Conn.SetReadDeadline(t)
}

func (l *LogConn) SetWriteDeadline(t time.Time) error {
	_, file, line, _ := runtime.Caller(4)
	fmt.Println("set write deadline", "time", t, "line", line, "file", file, "time", t)

	return l.Conn.SetWriteDeadline(t)
}

func IsConnectionTimedout(err error) bool {
	var se syscall.Errno

	if !errors.As(err, &se) {
		return false
	}

	return se == syscall.ETIMEDOUT
}
