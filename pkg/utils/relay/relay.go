package relay

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"reflect"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip"
)

var ignoreError = []error{
	io.EOF,
	// os.ErrDeadlineExceeded,
	net.ErrClosed,
}

var ignoreSyscallErrno = map[syscall.Errno]bool{
	syscall.EPIPE:      true, // broken pipe
	syscall.ECONNRESET: true, // connection reset by peer
	syscall.ENOTCONN:   true, // transport endpoint is not connected
	syscall.ETIMEDOUT:  true, // connection timed out
	10053:              true, // wsasend: An established connection was aborted by the software in your host machine." osSyscallErrType=syscall.Errno errInt=10053
	10054:              true, // wsarecv: An existing connection was forcibly closed by the remote host." osSyscallErrType=syscall.Errno errInt=10054
	10060:              true, // "wsarecv: A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond." osSyscallErrType=syscall.Errno errInt=10060
}

func isIgnoreError(err error) ([]any, bool) {
	if err == nil {
		return nil, true
	}

	for _, e := range ignoreError {
		if errors.Is(err, e) {
			return nil, true
		}
	}

	netOpErr := &net.OpError{}
	if !errors.As(err, &netOpErr) {
		return nil, false
	}
	switch netOpErr.Err.Error() {
	// netOp.Err is a string error
	//
	// netOpErr="read tcp [fc00::1a]:443: connection reset by peer" netOpErrType=*errors.errorString
	case syscall.ECONNRESET.Error():
		return nil, true
	case (&tcpip.ErrConnectionAborted{}).String(), (&tcpip.ErrAborted{}).String():
		return nil, true
	}

	args := []any{
		slog.Any("netOpErr", netOpErr),
		slog.Any("netOpErrType", reflect.TypeOf(netOpErr.Err)),
	}

	osSyscallErr := &os.SyscallError{}
	if !errors.As(netOpErr.Err, &osSyscallErr) {
		return args, false
	}

	// the Is [syscall.Errno.Is] function of syscall.Errno only check a little error code
	// so we check it by ourselves
	errInt, ok := osSyscallErr.Err.(syscall.Errno)
	if ok {
		if ignoreSyscallErrno[errInt] {
			return nil, true
		}

		args = append(args, slog.Any("osSyscallErrInt", errInt))
	}

	args = append(args, slog.Any("osSyscallErr", osSyscallErr))
	args = append(args, slog.Any("osSyscallErrType", reflect.TypeOf(osSyscallErr.Err)))

	return args, false
}

func logE(msg string, err error, cargs ...any) {
	if err == nil {
		return
	}
	args, ok := isIgnoreError(err)
	if ok {
		log.Select(slog.LevelDebug).PrintFunc(msg, func() []any { return append(cargs, slog.Any("err", err)) })
	} else {
		log.Error(msg, append(cargs, append(args, slog.Any("err", err), slog.Any("errType", reflect.TypeOf(err)))...)...)
	}
}

func AppendIgnoreError(err error) {
	ignoreError = append(ignoreError, err)
}

// Relay pipe
func Relay(rw1, rw2 io.ReadWriteCloser, logMsgs ...any) {
	logMsgs = append(logMsgs, slog.Any("rw1_type", reflect.TypeOf(rw1)), slog.Any("rw2_type", reflect.TypeOf(rw2)))
	wait := make(chan struct{})
	go func() {
		defer close(wait)
		_, err := Copy(rw2, rw1)
		logE("relay rw1 -> rw2", err, logMsgs...)
		closeWrite(rw2) // make another Copy exit
		closeRead(rw1)
	}()

	_, err := Copy(rw1, rw2)
	logE("relay rw2 -> rw1", err, logMsgs...)
	closeWrite(rw1)
	closeRead(rw2)

	<-wait
}

func closeRead(rw io.ReadWriteCloser) {
	if cr, ok := rw.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
	}
}

func closeWrite(rw io.ReadWriteCloser) {
	if r, ok := rw.(interface{ CloseWrite() error }); ok {
		if r.CloseWrite() == nil {
			return
		}
	}

	_ = rw.Close()
}

func Copy(dst io.Writer, src io.Reader) (n int64, err error) {
	buf := pool.GetBytes(8192)
	defer pool.PutBytes(buf)
	// to avoid using (*net.TCPConn).ReadFrom that will make new none-zero buf
	return io.CopyBuffer(WriteOnlyWriter{dst}, ReadOnlyReader{src}, buf)
}

func CopyN(dst io.Writer, src io.Reader, n int64) (written int64, err error) {
	if n <= 0 {
		return 0, nil
	}

	written, err = Copy(dst, io.LimitReader(src, n))
	if written == n {
		return n, nil
	}
	if written < n && err == nil {
		// src stopped early; must have been EOF.
		err = io.EOF
	}
	return
}

type ReadOnlyReader struct{ io.Reader }
type WriteOnlyWriter struct{ io.Writer }
