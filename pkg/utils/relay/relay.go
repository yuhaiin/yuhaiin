package relay

import (
	"io"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

// Relay pipe
func Relay(rw1, rw2 io.ReadWriter) {
	wait := make(chan struct{})
	go func() {
		defer close(wait)
		_ = Copy(rw2, rw1)
		setDeadline(rw2) // make another Copy exit
	}()

	_ = Copy(rw1, rw2)
	setDeadline(rw1)

	<-wait
}

func setDeadline(rw io.ReadWriter) {
	if r, ok := rw.(interface{ CloseWrite() error }); ok {
		r.CloseWrite()
		return
	}

	if r, ok := rw.(interface{ SetReadDeadline(time.Time) error }); ok {
		r.SetReadDeadline(time.Now())
	}
}

func Copy(dst io.Writer, src io.Reader) (err error) {
	buf := pool.GetBytes(nat.MaxSegmentSize)
	defer pool.PutBytes(buf)
	// to avoid using (*net.TCPConn).ReadFrom that will make new none-zero buf
	_, err = io.CopyBuffer(WriteOnlyWriter{dst}, ReadOnlyReader{src}, buf) // local -> remote
	return
}

type ReadOnlyReader struct {
	io.Reader
}

type WriteOnlyWriter struct {
	io.Writer
}
