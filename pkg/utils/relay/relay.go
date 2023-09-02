package relay

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

// Relay pipe
func Relay(rw1, rw2 io.ReadWriteCloser) {
	wait := make(chan struct{})
	go func() {
		defer close(wait)
		if _, err := Copy(rw2, rw1); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
			log.Error("relay rw1 -> rw2 failed", "err", err)
		}
		setDeadline(rw2) // make another Copy exit
	}()

	if _, err := Copy(rw1, rw2); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
		log.Error("relay rw2 -> rw1 failed", "err", err)
	}
	setDeadline(rw1)

	<-wait
}

func setDeadline(rw io.ReadWriteCloser) {
	if r, ok := rw.(interface{ CloseWrite() error }); ok {
		_ = r.CloseWrite()
		return
	}
	if r, ok := rw.(interface{ SetReadDeadline(time.Time) error }); ok {
		_ = r.SetReadDeadline(time.Now())
	} else {
		_ = rw.Close()
	}
}

func Copy(dst io.Writer, src io.Reader) (n int64, err error) {
	buf := pool.GetBytes(4096)
	defer pool.PutBytes(buf)
	// to avoid using (*net.TCPConn).ReadFrom that will make new none-zero buf
	return io.CopyBuffer(WriteOnlyWriter{dst}, ReadOnlyReader{src}, buf)
}

func CopyN(dst io.Writer, src io.Reader, n int64) (written int64, err error) {
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
