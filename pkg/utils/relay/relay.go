package relay

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

// Relay pipe
func Relay(local, remote io.ReadWriter) {
	wait := make(chan struct{})
	go func() {
		defer close(wait)
		if err := Copy(remote, local); err != nil && !errors.Is(err, io.EOF) {
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
				log.Errorln("relay local -> remote failed:", err)
			}
		}
		if r, ok := remote.(interface{ SetDeadline(time.Time) error }); ok {
			r.SetDeadline(time.Now().Add(-1)) // make another Copy exit
		}
	}()

	if err := Copy(local, remote); err != nil && !errors.Is(err, io.EOF) {
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			log.Errorln("relay remote -> local failed:", err)
		}
	}
	if r, ok := local.(interface{ SetDeadline(time.Time) error }); ok {
		r.SetDeadline(time.Now().Add(-1))
	}

	<-wait
}

func Copy(dst io.Writer, src io.Reader) (err error) {
	if c, ok := dst.(io.ReaderFrom); ok {
		_, err = c.ReadFrom(src) // local -> remote
	} else if c, ok := src.(io.WriterTo); ok {
		_, err = c.WriteTo(dst) // local -> remote
	} else {
		buf := pool.GetBytes(pool.DefaultSize)
		defer pool.PutBytes(buf)
		_, err = io.CopyBuffer(dst, src, buf) // local -> remote
	}

	return
}
