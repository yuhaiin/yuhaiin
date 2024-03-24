package relay

import (
	"errors"
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

var ignoreError = []error{
	io.EOF,
	// os.ErrDeadlineExceeded,
	// net.ErrClosed,
}

func logE(msg string, err error) {
	if err == nil {
		return
	}

	for _, e := range ignoreError {
		if errors.Is(err, e) {
			return
		}
	}

	log.Error(msg, "err", err)
}

func AppendIgnoreError(err error) {
	ignoreError = append(ignoreError, err)
}

// Relay pipe
func Relay(rw1, rw2 io.ReadWriteCloser) {
	wait := make(chan struct{})
	go func() {
		defer close(wait)
		_, err := Copy(rw2, rw1)
		logE("relay rw1 -> rw2", err)
		closeWrite(rw2) // make another Copy exit
		// closeRead(rw1)
	}()

	_, err := Copy(rw1, rw2)
	logE("relay rw2 -> rw1", err)
	closeWrite(rw1)
	// closeRead(rw2)

	<-wait
}

func closeRead(rw io.ReadWriteCloser) {
	if cr, ok := rw.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
	}
}

func closeWrite(rw io.ReadWriteCloser) {
	if r, ok := rw.(interface{ CloseWrite() error }); ok {
		_ = r.CloseWrite()
		return
	}

	_ = rw.Close()
}

func Copy(dst io.Writer, src io.Reader) (n int64, err error) {
	buf := pool.GetBytes(pool.DefaultSize)
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
