package gateway

import (
	"io"
	"sync"
)

type responseBody struct {
	io.ReadCloser
	release func()
}

func (b *responseBody) Close() error { err := b.ReadCloser.Close(); b.release(); return err }
func (b *responseBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.release()
	}
	return n, err
}

// HTTP Upgrade requires io.ReadWriteCloser; preserve that optional capability.
type upgradedBody struct {
	*responseBody
	writer io.Writer
}

func (b upgradedBody) Write(p []byte) (int, error) { return b.writer.Write(p) }
func wrapResponseBody(body io.ReadCloser, release func()) io.ReadCloser {
	b := &responseBody{body, sync.OnceFunc(release)}
	if w, ok := body.(io.Writer); ok {
		return upgradedBody{b, w}
	}
	return b
}
