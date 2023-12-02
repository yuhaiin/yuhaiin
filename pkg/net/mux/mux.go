package mux

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
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
}

type connEntry struct {
	mu      sync.Mutex
	session *IdleSession
}

type MuxClient struct {
	netapi.Proxy
	selector *randomSelector
}

func NewClient(config *protocol.Protocol_Mux) protocol.WrapProxy {
	return func(dialer netapi.Proxy) (netapi.Proxy, error) {
		if config.Mux.Concurrency <= 0 {
			config.Mux.Concurrency = 1
		}

		// TODO: remove underlying connection limit
		if config.Mux.Concurrency > 16 {
			config.Mux.Concurrency = 16
		}

		c := &MuxClient{
			Proxy:    dialer,
			selector: NewRandomSelector(int(config.Mux.Concurrency)),
		}

		return c, nil
	}
}

func (m *MuxClient) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	session, err := m.nexSession(ctx)
	if err != nil {
		return nil, err
	}

	conn, err := session.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("yamux open error: %w", err)
	}

	return conn, nil
}

func (m *MuxClient) nexSession(ctx context.Context) (*IdleSession, error) {
	entry := m.selector.Select()

	if entry.session != nil && !entry.session.IsClosed() {
		return entry.session, nil
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
	mu    sync.Mutex
	timer *time.Timer
	*yamux.Session
}

func NewIdleSession(session *yamux.Session, IdleTimeout time.Duration) *IdleSession {
	s := &IdleSession{
		Session: session,
	}

	go func() {
		ticker := time.NewTicker(IdleTimeout)
		defer ticker.Stop()

		for {
			select {
			case <-session.CloseChan():
				return
			case <-ticker.C:
				if session.NumStreams() != 0 {
					continue
				}

				s.mu.Lock()
				if s.timer == nil && session.NumStreams() == 0 {
					s.timer = time.AfterFunc(IdleTimeout, func() {
						if session.NumStreams() == 0 {
							session.Close()
						}
					})
				}
				s.mu.Unlock()
			}
		}
	}()

	return s
}

func (i *IdleSession) stopTimer() {
	if i.timer != nil {
		i.mu.Lock()
		defer i.mu.Unlock()

		if i.timer == nil {
			return
		}

		i.timer.Stop()
		i.timer = nil
	}
}

func (i *IdleSession) OpenStream(ctx context.Context) (*yamux.Stream, error) {
	i.stopTimer()
	return i.Session.OpenStream(ctx)
}

func (i *IdleSession) Open(ctx context.Context) (net.Conn, error) {
	i.stopTimer()
	return i.Session.Open(ctx)
}

type muxConn struct {
	*yamux.Stream
}

func (m *muxConn) RemoteAddr() net.Addr {
	return &MuxAddr{
		Addr: m.Stream.RemoteAddr(),
		ID:   m.StreamID(),
	}
}

type MuxAddr struct {
	Addr net.Addr
	ID   uint32
}

func (q *MuxAddr) String() string  { return fmt.Sprint(q.Addr, q.ID) }
func (q *MuxAddr) Network() string { return "yamux" }

type randomSelector struct {
	content []*connEntry
}

func NewRandomSelector(cap int) *randomSelector {
	content := make([]*connEntry, cap)

	for i := 0; i < cap; i++ {
		content[i] = &connEntry{}
	}

	return &randomSelector{
		content: content,
	}
}

func (s *randomSelector) Select() *connEntry {
	return s.content[rand.Intn(len(s.content))]
}
