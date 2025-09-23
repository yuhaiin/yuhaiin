// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package pipe

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// PipeDeadline is an abstraction for handling timeouts.
type PipeDeadline struct {
	timer  *time.Timer
	cancel chan struct{} // Must be non-nil
	mu     sync.Mutex    // Guards timer and cancel
}

func MakePipeDeadline() PipeDeadline {
	return PipeDeadline{cancel: make(chan struct{})}
}

// Set sets the point in time when the deadline will time out.
// A timeout event is signaled by closing the channel returned by waiter.
// Once a timeout has occurred, the deadline can be refreshed by specifying a
// t value in the future.
//
// A zero value for t prevents timeout.
func (d *PipeDeadline) Set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // Wait for the timer callback to finish and close cancel
	}
	d.timer = nil

	// Time is zero, then there is no deadline.
	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}

	// Time in the future, setup a timer to cancel in the future.
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		d.timer = time.AfterFunc(dur, func() {
			close(d.cancel)
		})
		return
	}

	// Time in the past, so close immediately.
	if !closed {
		close(d.cancel)
	}
}

// Wait returns a channel that is closed when the deadline is exceeded.
func (d *PipeDeadline) Wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe:0" }

type Conn struct {

	// Used by local Read to interact with remote Write.
	// Successful receive on rdRx is always followed by send on rdTx.
	rdRx <-chan []byte
	rdTx chan<- int

	// Used by local Write to interact with remote Read.
	// Successful send on wrTx is always followed by receive on wrRx.
	wrTx chan<- []byte
	wrRx <-chan int

	localDone       chan struct{}
	remoteDone      <-chan struct{}
	localWriteDone  chan struct{}
	remoteWriteDone <-chan struct{}

	localAddr  atomic.Pointer[net.Addr]
	remoteAddr atomic.Pointer[net.Addr]

	onClose atomic.Pointer[func()]

	readDeadline  PipeDeadline
	writeDeadline PipeDeadline

	once      sync.Once // Protects closing localDone
	writeOnce sync.Once
	wrMu      sync.Mutex // Serialize Write operations

}

// Pipe creates a synchronous, in-memory, full duplex
// network connection; both ends implement the [Conn] interface.
// Reads on one end are matched with writes on the other,
// copying data directly between the two; there is no internal
// buffering.
func Pipe() (*Conn, *Conn) {
	cb1 := make(chan []byte)
	cb2 := make(chan []byte)
	cn1 := make(chan int)
	cn2 := make(chan int)
	done1 := make(chan struct{})
	done2 := make(chan struct{})
	writeDone1 := make(chan struct{})
	writeDone2 := make(chan struct{})

	p1 := &Conn{
		rdRx: cb1, rdTx: cn1,
		wrTx: cb2, wrRx: cn2,
		localDone: done1, remoteDone: done2,
		localWriteDone: writeDone1, remoteWriteDone: writeDone2,
		readDeadline:  MakePipeDeadline(),
		writeDeadline: MakePipeDeadline(),
	}
	p2 := &Conn{
		rdRx: cb2, rdTx: cn2,
		wrTx: cb1, wrRx: cn1,
		localDone: done2, remoteDone: done1,
		localWriteDone: writeDone2, remoteWriteDone: writeDone1,
		readDeadline:  MakePipeDeadline(),
		writeDeadline: MakePipeDeadline(),
	}
	return p1, p2
}

func (c *Conn) SetLocalAddr(addr net.Addr) {
	if addr == nil {
		return
	}
	c.localAddr.Store(&addr)
}

func (c *Conn) SetRemoteAddr(addr net.Addr) {
	if addr == nil {
		return
	}
	c.remoteAddr.Store(&addr)
}

func (c *Conn) LocalAddr() net.Addr {
	if addr := c.localAddr.Load(); addr != nil {
		return *addr
	}
	return pipeAddr{}
}

func (c *Conn) RemoteAddr() net.Addr {
	if addr := c.remoteAddr.Load(); addr != nil {
		return *addr
	}
	return pipeAddr{}
}

func (p *Conn) Read(b []byte) (int, error) {
	n, err := p.read(b)
	if err != nil && err != io.EOF && err != io.ErrClosedPipe {
		err = &net.OpError{Op: "read", Net: "pipe", Err: err}
	}
	return n, err
}

func (p *Conn) read(b []byte) (n int, err error) {
	switch {
	case isClosedChan(p.localDone):
		return 0, io.ErrClosedPipe
	case isClosedChan(p.remoteDone), isClosedChan(p.remoteWriteDone):
		return 0, io.EOF
	case isClosedChan(p.readDeadline.Wait()):
		return 0, os.ErrDeadlineExceeded
	}

	select {
	case bw := <-p.rdRx:
		nr := copy(b, bw)
		p.rdTx <- nr
		return nr, nil
	case <-p.localDone:
		return 0, io.ErrClosedPipe
	case <-p.remoteDone:
		return 0, io.EOF
	case <-p.remoteWriteDone:
		return 0, io.EOF
	case <-p.readDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	}
}

func (p *Conn) Write(b []byte) (int, error) {
	n, err := p.write(b)
	if err != nil && err != io.ErrClosedPipe {
		err = &net.OpError{Op: "write", Net: "pipe", Err: err}
	}
	return n, err
}

func (p *Conn) write(b []byte) (n int, err error) {
	switch {
	case isClosedChan(p.localDone):
		return 0, io.ErrClosedPipe
	case isClosedChan(p.localWriteDone):
		return 0, io.ErrClosedPipe
	case isClosedChan(p.remoteDone):
		return 0, io.ErrClosedPipe
	case isClosedChan(p.writeDeadline.Wait()):
		return 0, os.ErrDeadlineExceeded
	}

	p.wrMu.Lock() // Ensure entirety of b is written together
	defer p.wrMu.Unlock()
	for once := true; once || len(b) > 0; once = false {
		select {
		case p.wrTx <- b:
			nw := <-p.wrRx
			b = b[nw:]
			n += nw
		case <-p.localDone:
			return n, io.ErrClosedPipe
		case <-p.localWriteDone:
			return n, io.ErrClosedPipe
		case <-p.remoteDone:
			return n, io.ErrClosedPipe
		case <-p.writeDeadline.Wait():
			return n, os.ErrDeadlineExceeded
		}
	}
	return n, nil
}

func (p *Conn) SetDeadline(t time.Time) error {
	if isClosedChan(p.localDone) || isClosedChan(p.remoteDone) {
		return io.ErrClosedPipe
	}
	p.readDeadline.Set(t)
	p.writeDeadline.Set(t)
	return nil
}

func (p *Conn) SetReadDeadline(t time.Time) error {
	if isClosedChan(p.localDone) || isClosedChan(p.remoteDone) || isClosedChan(p.remoteWriteDone) {
		return io.ErrClosedPipe
	}
	p.readDeadline.Set(t)
	return nil
}

func (p *Conn) SetWriteDeadline(t time.Time) error {
	if isClosedChan(p.localDone) || isClosedChan(p.remoteDone) || isClosedChan(p.localWriteDone) {
		return io.ErrClosedPipe
	}
	p.writeDeadline.Set(t)
	return nil
}

func (p *Conn) SetOnClose(f func()) { p.onClose.Store(&f) }

func (p *Conn) Close() error {
	p.once.Do(func() {
		if close := p.onClose.Load(); close != nil {
			(*close)()
		}
		close(p.localDone)
	})
	p.writeOnce.Do(func() { close(p.localWriteDone) })
	return nil
}

func (p *Conn) CloseWrite() error {
	p.writeOnce.Do(func() { close(p.localWriteDone) })
	return nil
}
