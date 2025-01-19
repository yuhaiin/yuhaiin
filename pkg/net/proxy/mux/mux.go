package mux

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/libp2p/go-yamux/v4"
)

var config *yamux.Config

func init() {
	config = yamux.DefaultConfig()
	// We've bumped this to 16MiB as this critically limits throughput.
	//
	// 1MiB means a best case of 10MiB/s (83.89Mbps) on a connection with
	// 100ms latency. The default gave us 2.4MiB *best case* which was
	// totally unacceptable.
	config.MaxStreamWindowSize = uint32(16 * 1024 * 1024)
	// don't spam
	config.LogOutput = io.Discard
	// We always run over a security transport that buffers internally
	// (i.e., uses a block cipher).
	config.ReadBufSize = 0
	// Effectively disable the incoming streams limit.
	// This is now dynamically limited by the resource manager.
	config.MaxIncomingStreams = math.MaxUint32
	// Disable keepalive, we don't need it
	// tcp keepalive will used in underlying conn
	config.EnableKeepAlive = false

	config.ConnectionWriteTimeout = 4*time.Second + time.Second/2

	relay.AppendIgnoreError(yamux.ErrStreamReset)
}

type connEntry struct {
	session *IdleSession
	mu      sync.Mutex
}

func (c *connEntry) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	err := c.session.Close()
	c.session = nil

	return err
}

type MuxClient struct {
	netapi.Proxy
	selector *rangeSelector
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *protocol.Mux) register.WrapProxy {
	return func(dialer netapi.Proxy) (netapi.Proxy, error) {
		if config.GetConcurrency() <= 0 {
			config.SetConcurrency(1)
		}

		c := &MuxClient{
			Proxy:    dialer,
			selector: NewRangeSelector(int(config.GetConcurrency())),
		}

		return c, nil
	}
}

func (m *MuxClient) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	session, err := m.nextSession(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := session.OpenStream(ctx)
	if err != nil {
		session.closed = true
		return nil, fmt.Errorf("yamux open error: %w", err)
	}

	return &muxConn{conn}, nil
}

func (m *MuxClient) nextSession(ctx context.Context) (*IdleSession, error) {
	entry := m.selector.Select()

	session := entry.session

	if session != nil && !session.IsClosed() {
		return session, nil
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.session != nil && !entry.session.IsClosed() {
		return entry.session, nil
	}

	dc, err := m.Proxy.Conn(ctx, netapi.EmptyAddr)
	if err != nil {
		return nil, err
	}

	yamuxSession, err := yamux.Client(dc, config, nil)
	if err != nil {
		dc.Close()
		return nil, fmt.Errorf("yamux client error: %w", err)
	}

	entry.session = NewIdleSession(yamuxSession, time.Minute*2)

	return entry.session, nil
}

type IdleSession struct {
	*yamux.Session
	timer       *time.Timer
	idleTimeout time.Duration
	closed      bool
}

func NewIdleSession(session *yamux.Session, IdleTimeout time.Duration) *IdleSession {
	s := &IdleSession{
		Session:     session,
		idleTimeout: IdleTimeout,
	}

	s.timer = time.AfterFunc(IdleTimeout, func() {
		if session.NumStreams() != 0 {
			s.timer.Reset(IdleTimeout)
		} else {
			session.Close()
		}
	})

	return s
}

func (i *IdleSession) OpenStream(ctx context.Context) (*yamux.Stream, error) {
	i.timer.Reset(i.idleTimeout)
	return i.Session.OpenStream(ctx)
}

func (i *IdleSession) Open(ctx context.Context) (net.Conn, error) {
	i.timer.Reset(i.idleTimeout)
	return i.Session.Open(ctx)
}

func (i *IdleSession) IsClosed() bool {
	if i.closed {
		return true
	}

	return i.Session.IsClosed()
}

func (i *IdleSession) Close() error {
	i.timer.Stop()
	return i.Session.Close()
}

type MuxConn interface {
	net.Conn
	StreamID() uint32
}

type muxConn struct {
	MuxConn // must not *yamux.Stream, the close write is not a really close write
}

func (m *muxConn) RemoteAddr() net.Addr {
	return &MuxAddr{
		Addr: m.MuxConn.RemoteAddr(),
		ID:   m.StreamID(),
	}
}

// func (m *muxConn) Read(p []byte) (n int, err error) {
// 	n, err = m.MuxConn.Read(p)
// 	if err != nil {
// 		if errors.Is(err, yamux.ErrStreamReset) || errors.Is(err, yamux.ErrStreamClosed) {
// 			err = io.EOF
// 		}
// 	}

// 	return
// }

type MuxAddr struct {
	Addr net.Addr
	ID   uint32
}

func (q *MuxAddr) String() string  { return fmt.Sprintf("yamux://%d@%v", q.ID, q.Addr) }
func (q *MuxAddr) Network() string { return "tcp" }

type rangeSelector struct {
	content []*connEntry
	cap     uint64
	count   atomic.Uint64
}

func NewRangeSelector(cap int) *rangeSelector {
	content := make([]*connEntry, cap)

	for i := 0; i < cap; i++ {
		content[i] = &connEntry{}
	}

	return &rangeSelector{
		content: content,
		cap:     uint64(cap),
	}
}

func (s *rangeSelector) Select() *connEntry {
	return s.content[s.count.Add(1)%s.cap]
}
