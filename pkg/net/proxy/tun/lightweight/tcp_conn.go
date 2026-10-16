package lightweight

import (
	"container/list"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const segmentCharge = 256
const receiveCharge = 128
const maxSendSegments = 16384
const maxReceiveChunks = 8192

func segmentMemory(v *sendSegment) int {
	if v.owner == nil {
		return 0
	}
	return segmentCharge
}

type sendSegment struct {
	owner                    *ownedBuffer
	seq                      uint32
	flags                    uint8
	data                     []byte
	sent, firstSent          time.Time
	transmissions            int
	sacked                   bool
	resend                   bool
	delivered                uint64
	deliveredAt, firstFlight time.Time
	appLimited               bool
}

func (s *sendSegment) length() uint32 {
	n := uint32(len(s.data))
	if s.flags&(flagSYN|flagFIN) != 0 {
		n++
	}
	return n
}

type receiveChunk struct {
	owner  *ownedBuffer
	data   []byte
	offset int
}
type receivePiece struct {
	owner *ownedBuffer
	seq   uint32
	data  []byte
}

// TCPConn serializes protocol state with mu. Application writes additionally
// take writeMu; Close never takes writeMu and always interrupts a blocked Write.
// No callback retains caller-owned read/write buffers. Queued bytes belong to
// this connection until consumed/ACKed, or until finish releases them.
type TCPConn struct {
	outputEntry                                              *list.Element
	outputWaiting                                            bool
	outputBytes                                              int
	outputReady                                              atomic.Bool
	stack                                                    *Stack
	key                                                      flowKey
	mu, writeMu                                              sync.Mutex
	changed                                                  chan struct{}
	state                                                    TCPState
	listener                                                 *TCPListener
	controller                                               congestion.Controller
	iss, sndUna, sndNxt, sndEnd, rcvNxt, rcvAdv              uint32
	sndWL1, sndWL2, peerWindow                               uint32
	ownScale, peerScale                                      int
	mss, pathMSS                                             int
	sack                                                     bool
	tx                                                       sliceQueue[*sendSegment]
	txBytes                                                  int
	bytesInFlight                                            uint64
	rx                                                       sliceQueue[receiveChunk]
	ooo                                                      []receivePiece
	rxBytes, receiveLimit, consumed                          int
	growthAt                                                 time.Time
	finPending                                               bool
	finSeq                                                   uint32
	recvFIN                                                  bool
	readClosed, writeClosed, appClosed                       bool
	err                                                      error
	readDeadline, writeDeadline                              time.Time
	srtt, rttvar, rto                                        time.Duration
	rtoAt, paceAt, ackAt, persistAt, endAt, born, lastActive time.Time
	retries, dupACKs, ackPending, keepaliveSent              int
	recovering                                               bool
	recover                                                  uint32
	delivered                                                uint64
	deliveredAt, firstFlight                                 time.Time
	job                                                      timerJob
	persistProbes                                            int
}

var _ net.Conn = (*TCPConn)(nil)

func (c *TCPConn) LocalAddr() net.Addr  { return net.TCPAddrFromAddrPort(c.key.local) }
func (c *TCPConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.key.remote) }
func (c *TCPConn) State() TCPState      { c.mu.Lock(); defer c.mu.Unlock(); return c.state }
func (c *TCPConn) errorLocked() error {
	if c.err != nil {
		return c.err
	}
	return net.ErrClosed
}
func (c *TCPConn) abort(err error) { c.mu.Lock(); defer c.mu.Unlock(); c.finish(err) }
func (c *TCPConn) finish(err error) {
	if c.state == Closed {
		if err != nil {
			c.clearReceive()
			c.stack.remove(c)
		}
		return
	}
	c.state = Closed
	c.cancelOutputWait()
	c.err = err
	for _, v := range c.tx.values() {
		v.owner.release()
		c.stack.release(segmentMemory(v))
	}
	c.tx.reset()
	c.txBytes = 0
	c.bytesInFlight = 0
	if err != nil {
		c.clearReceive()
	}
	c.stack.scheduler.set(&c.job, time.Time{})
	if c.rxBytes == 0 {
		c.stack.remove(c)
	}
	notify(&c.changed)
}
func (c *TCPConn) clearReceive() {
	for _, v := range c.rx.values() {
		v.owner.release()
		c.stack.release(receiveCharge)
	}
	for _, v := range c.ooo {
		v.owner.release()
		c.stack.release(receiveCharge)
	}
	c.rx.reset()
	c.ooo = nil
	c.rxBytes = 0
}
func (c *TCPConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	out, err := c.ReadWithBuffer(func() []byte { return b })
	return len(out), err
}

// ReadWithBuffer structurally implements netapi.BufferReader without importing
// netapi. The caller's allocator is invoked only when data is ready.
func (c *TCPConn) ReadWithBuffer(get func() []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.appClosed {
			return nil, net.ErrClosed
		}
		if c.readClosed {
			return nil, io.EOF
		}
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			return nil, os.ErrDeadlineExceeded
		}
		if c.rx.len() > 0 {
			b := get()
			if len(b) == 0 {
				return b, io.ErrShortBuffer
			}
			n := 0
			for c.rx.len() > 0 && n < len(b) {
				v := &c.rx.values()[0]
				k := copy(b[n:], v.data[v.offset:])
				v.offset += k
				n += k
				c.rxBytes -= k
				if v.offset == len(v.data) {
					v.owner.release()
					c.stack.release(receiveCharge)
					c.rx.pop()
				}
			}
			if c.state == Closed && c.rxBytes == 0 {
				c.stack.remove(c)
			}
			c.consumed += n
			now := time.Now()
			window := c.receiveWindow()
			period := max(c.srtt, 10*time.Millisecond)
			if c.consumed >= c.receiveLimit/2 {
				if !c.growthAt.IsZero() && now.Sub(c.growthAt) <= 2*period {
					c.receiveLimit = min(c.stack.config.MaxReceiveBuffer, 2*c.receiveLimit)
				}
				c.growthAt = now
				c.consumed = 0
			}
			if uint32(c.receiveWindow()) > window && window < uint32(c.receiveLimit/2) || c.rcvAdv-c.rcvNxt < uint32(c.receiveLimit/2) {
				c.sendACK()
			}
			c.schedule(now)
			return b[:n], nil
		}
		if c.recvFIN {
			return nil, io.EOF
		}
		if c.state == Closed {
			return nil, c.errorLocked()
		}
		ch, at := watch(&c.changed), c.readDeadline
		c.mu.Unlock()
		err := waitSocket(ch, c.stack.done, at)
		c.mu.Lock()
		if err != nil {
			return nil, err
		}
	}
}
func (c *TCPConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for written < len(b) {
		if c.appClosed || c.writeClosed {
			return written, net.ErrClosed
		}
		if c.state == Closed {
			return written, c.errorLocked()
		}
		if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
			return written, os.ErrDeadlineExceeded
		}
		available := c.stack.config.SendBuffer - c.txBytes
		if available <= 0 || c.tx.len() >= maxSendSegments {
			ch, at := watch(&c.changed), c.writeDeadline
			c.mu.Unlock()
			err := waitSocket(ch, c.stack.done, at)
			c.mu.Lock()
			if err != nil {
				return written, err
			}
			continue
		}
		// Copy a bounded application chunk once; MSS-sized retransmission views
		// share that immutable allocation until every view is cumulatively ACKed.
		n := min(len(b)-written, available, 16384, (maxSendSegments-c.tx.len())*c.mss)
		owner, err := c.stack.buffers.get(n)
		if err != nil {
			return written, err
		}
		copy(owner.data, b[written:written+n])
		for off := 0; off < n; {
			if !c.stack.reserve(segmentCharge) {
				owner.release()
				c.pump(time.Now())
				return written, ErrLimit
			}
			end := min(n, off+c.mss)
			owner.hold()
			c.tx.push(&sendSegment{seq: c.sndEnd, flags: flagACK | flagPSH, data: owner.data[off:end], owner: owner})
			k := end - off
			c.sndEnd += uint32(k)
			c.txBytes += k
			written += k
			off = end
		}
		owner.release()
		c.pump(time.Now())
	}
	return written, nil
}
func (c *TCPConn) CloseWrite() error { c.mu.Lock(); defer c.mu.Unlock(); return c.closeWriteLocked() }
func (c *TCPConn) closeWriteLocked() error {
	if c.writeClosed {
		return nil
	}
	if c.state == Closed {
		return c.errorLocked()
	}
	c.writeClosed = true
	switch c.state {
	case Established:
		c.state = FinWait1
	case CloseWait:
		c.state = LastAck
	default:
		return net.ErrClosed
	}
	c.enqueueControl(flagFIN)
	c.pump(time.Now())
	notify(&c.changed)
	return nil
}
func (c *TCPConn) CloseRead() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readClosed = true
	c.clearReceive()
	c.sendACK()
	notify(&c.changed)
	return nil
}
func (c *TCPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.appClosed {
		return nil
	}
	c.appClosed = true
	if c.state == Closed {
		c.clearReceive()
		c.stack.remove(c)
		notify(&c.changed)
		return nil
	}
	if c.rxBytes > 0 || c.state == SynSent || c.state == SynReceived {
		c.sendReset()
		c.finish(net.ErrClosed)
		return nil
	}
	c.readClosed = true
	_ = c.closeWriteLocked()
	notify(&c.changed)
	return nil
}
func (c *TCPConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	notify(&c.changed)
	return nil
}
func (c *TCPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	notify(&c.changed)
	return nil
}
func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	notify(&c.changed)
	return nil
}
func (c *TCPConn) enqueueControl(flags uint8) {
	c.tx.push(&sendSegment{seq: c.sndEnd, flags: flags})
	c.sndEnd++
	if flags&flagFIN != 0 {
		c.endAt = time.Now().Add(2 * time.Minute)
	}
}
