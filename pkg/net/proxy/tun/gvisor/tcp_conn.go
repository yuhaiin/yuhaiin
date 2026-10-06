package gvisor

import (
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/waiter"
)

func newTCPConn(wq *waiter.Queue, ep tcpip.Endpoint) net.Conn {
	e := &bufferedTCPEndpoint{Endpoint: ep}
	return &tcpConn{TCPConn: gonet.NewTCPConn(wq, e), endpoint: e}
}

// Keep gonet's read/deadline/notification implementation, but replace its slice
// writer on buffered reads. TCP only calls Write when data is available, so
// the caller's relay buffer need not be leased during the idle wait.
type tcpConn struct {
	*gonet.TCPConn
	readMu   sync.Mutex
	endpoint *bufferedTCPEndpoint
}

var _ netapi.BufferReader = (*tcpConn)(nil)

func (c *tcpConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.TCPConn.Read(b)
}

func (c *tcpConn) ReadWithBuffer(getBuffer func() []byte) ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	e := c.endpoint
	w := &e.writer
	w.getBuffer = getBuffer
	e.buffered = true
	defer func() {
		w.getBuffer = nil
		w.buffer = nil
		w.remaining = nil
		e.buffered = false
	}()
	n, err := c.TCPConn.Read(nil)
	if w.buffer == nil {
		return nil, err
	}
	return w.buffer[:n], err
}

// Read and ReadWithBuffer serialize access to these fields. No other endpoint
// operation uses them. Returned storage belongs to the caller, not the endpoint.
type bufferedTCPEndpoint struct {
	tcpip.Endpoint
	writer   tcpReadWriter
	buffered bool
}

func (e *bufferedTCPEndpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	if e.buffered {
		dst = &e.writer
	}
	return e.Endpoint.Read(dst, opts)
}

type tcpReadWriter struct {
	getBuffer func() []byte
	buffer    []byte
	remaining []byte
}

func (e *tcpReadWriter) Write(data []byte) (int, error) {
	if e.getBuffer != nil {
		e.buffer = e.getBuffer()
		e.remaining = e.buffer
		e.getBuffer = nil
	}
	n := copy(e.remaining, data)
	e.remaining = e.remaining[n:]
	if n < len(data) {
		return n, io.ErrShortWrite
	}
	return n, nil
}
