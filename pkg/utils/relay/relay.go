package relay

import (
	"errors"
	"io"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/libp2p/go-yamux/v4"
)

// Relay pipe
func Relay(rw1, rw2 io.ReadWriteCloser) {
	wait := make(chan struct{})
	go func() {
		defer close(wait)
		if _, err := Copy(rw2, rw1); err != nil &&
			!errors.Is(err, io.EOF) &&
			!errors.Is(err, os.ErrDeadlineExceeded) &&
			!errors.Is(err, yamux.ErrTimeout) &&
			!errors.Is(err, net.ErrClosed) {
			log.Error("relay rw1 -> rw2 failed", "err", err)
		}
		closeWrite(rw2) // make another Copy exit
		// closeRead(rw1)
	}()

	if _, err := Copy(rw1, rw2); err != nil &&
		!errors.Is(err, io.EOF) &&
		!errors.Is(err, os.ErrDeadlineExceeded) &&
		!errors.Is(err, yamux.ErrTimeout) &&
		!errors.Is(err, net.ErrClosed) {
		log.Error("relay rw2 -> rw1 failed", "err", err)
	}
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

	// if r, ok := rw.(interface{ SetReadDeadline(time.Time) error }); ok {
	// 	_ = r.SetReadDeadline(time.Now())
	// } else {
	_ = rw.Close()
	// }
}

func Copy(dst io.Writer, src io.Reader) (n int64, err error) {
	buf := pool.GetBytes(pool.DefaultSize)
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
