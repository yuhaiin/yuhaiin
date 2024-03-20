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
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
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
	mu      sync.Mutex
	session *IdleSession
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
	point.RegisterProtocol(NewClient)
}

func NewClient(config *protocol.Protocol_Mux) point.WrapProxy {
	return func(dialer netapi.Proxy) (netapi.Proxy, error) {
		if config.Mux.Concurrency <= 0 {
			config.Mux.Concurrency = 1
		}

		c := &MuxClient{
			Proxy:    dialer,
			selector: NewRangeSelector(int(config.Mux.Concurrency)),
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

	entry.session = NewIdleSession(yamuxSession, time.Minute)

	return entry.session, nil
}

type IdleSession struct {
	closed bool
	*yamux.Session

	lastStreamTime *atomic.Pointer[time.Time]
}

func NewIdleSession(session *yamux.Session, IdleTimeout time.Duration) *IdleSession {
	s := &IdleSession{
		Session:        session,
		lastStreamTime: &atomic.Pointer[time.Time]{},
	}

	s.updateLatestStreamTime()

	go func() {
		readyClose := false
		ticker := time.NewTicker(IdleTimeout)
		defer ticker.Stop()

		for {
			select {
			case <-session.CloseChan():
				return
			case <-ticker.C:
				if session.NumStreams() != 0 {
					readyClose = false
					continue
				}

				if time.Since(*s.lastStreamTime.Load()) < IdleTimeout {
					readyClose = false
					continue
				}

				if readyClose {
					session.Close()
					return
				}

				readyClose = true
			}
		}
	}()

	return s
}

func (i *IdleSession) updateLatestStreamTime() {
	now := time.Now()
	i.lastStreamTime.Store(&now)
}

func (i *IdleSession) OpenStream(ctx context.Context) (*yamux.Stream, error) {
	i.updateLatestStreamTime()
	return i.Session.OpenStream(ctx)
}

func (i *IdleSession) Open(ctx context.Context) (net.Conn, error) {
	i.updateLatestStreamTime()
	return i.Session.Open(ctx)
}

func (i *IdleSession) IsClosed() bool {
	if i.closed {
		return true
	}

	return i.Session.IsClosed()
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
