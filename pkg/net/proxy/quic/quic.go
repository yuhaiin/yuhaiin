package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/quic-go/quic-go"
)

type Client struct {
	netapi.EmptyDispatch

	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	dialer      netapi.Proxy
	session     quic.Connection
	fragSession *ConnectionPacketConn
	sessionMu   sync.Mutex

	id     id.IDGenerator
	udpMap map[uint64]chan packet
	udpMu  sync.RWMutex
}

func New(config *protocol.Protocol_Quic) protocol.WrapProxy {
	return func(dialer netapi.Proxy) (netapi.Proxy, error) {
		log.Debug("new quic", "config", config)

		tlsConfig := protocol.ParseTLSConfig(config.Quic.Tls)
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		}

		c := &Client{
			dialer:    dialer,
			tlsConfig: tlsConfig,
			quicConfig: &quic.Config{
				MaxIdleTimeout:  20 * time.Second,
				KeepAlivePeriod: 20 * time.Second * 2 / 5,
				EnableDatagrams: true,
			},

			udpMap: make(map[uint64]chan packet),
		}

		return c, nil
	}
}

func (c *Client) initSession(ctx context.Context) error {
	if c.session != nil {
		select {
		case <-c.session.Context().Done():
		default:
			return nil
		}
	}

	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()

	if c.session != nil {
		select {
		case <-c.session.Context().Done():
		default:
			return nil
		}
	}

	conn, err := c.dialer.PacketConn(ctx, netapi.EmptyAddr)
	if err != nil {
		return err
	}

	session, err := quic.Dial(ctx, conn, &net.UDPAddr{IP: net.IPv4zero}, c.tlsConfig, c.quicConfig)
	if err != nil {
		return err
	}

	go func() {
		defer log.Debug("session closed")
		defer conn.Close()                                                          //nolint:errcheck
		defer c.session.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "") //nolint:errcheck

		conn := NewConnectionPacketConn(context.Background(), c.session)

		for {
			id, b, addr, err := conn.Receive()
			if err != nil {
				break
			}

			if err = c.handleDatagrams(id, addr, b); err != nil {
				log.Debug("handle datagrams failed:", "err", err)
			}
		}
	}()

	c.session = session
	c.fragSession = NewConnectionPacketConn(ctx, session)
	return nil
}

func (c *Client) handleDatagrams(id uint16, addr net.Addr, b []byte) error {
	c.udpMu.RLock()
	defer c.udpMu.RUnlock()

	x, ok := c.udpMap[uint64(id)]
	if !ok {
		return fmt.Errorf("unknown udp id: %d, %v", id, b[:2])
	}

	x <- packet{data: b, addr: addr}

	return nil
}

func (c *Client) Conn(ctx context.Context, s netapi.Address) (net.Conn, error) {
	if err := c.initSession(ctx); err != nil {
		log.Error("init session failed:", "err", err)
		return nil, err
	}

	stream, err := c.session.OpenStream()
	if err != nil {
		return nil, err
	}

	return &interConn{
		Stream: stream,
		local:  c.session.LocalAddr(),
		remote: s,
	}, nil
}

func (c *Client) PacketConn(ctx context.Context, host netapi.Address) (net.PacketConn, error) {
	if err := c.initSession(ctx); err != nil {
		return nil, err
	}

	id := c.id.Generate()
	msgChan := make(chan packet, 30)

	c.udpMu.Lock()
	c.udpMap[id] = msgChan
	c.udpMu.Unlock()

	return &interPacketConn{
		c:       c,
		session: c.fragSession,
		msgChan: msgChan,
		id:      uint16(id),
	}, nil
}

var _ net.Conn = (*interConn)(nil)

type interConn struct {
	quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *interConn) Close() error {
	c.Stream.CancelRead(0)

	var err error
	if er := c.Stream.Close(); er != nil {
		err = errors.Join(err, er)
	}

	return err
}

func (c *interConn) LocalAddr() net.Addr { return c.local }

func (c *interConn) RemoteAddr() net.Addr { return c.remote }

type packet struct {
	data []byte
	addr net.Addr
}
type interPacketConn struct {
	session *ConnectionPacketConn
	msgChan chan packet
	id      uint16

	c *Client

	closed bool

	deadline *time.Timer
}

func (x *interPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if x.closed {
		return 0, nil, net.ErrClosed
	}

	msg, ok := <-x.msgChan
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n = copy(p, msg.data)

	return n, msg.addr, nil
}

func (x *interPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if x.closed {
		return 0, net.ErrClosed
	}

	err = x.session.Write(p, x.id, addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (x *interPacketConn) Close() error {
	x.c.udpMu.Lock()
	defer x.c.udpMu.Unlock()

	if x.closed {
		return nil
	}

	delete(x.c.udpMap, uint64(x.id))
	close(x.msgChan)
	x.closed = true

	return nil
}

func (x *interPacketConn) LocalAddr() net.Addr {
	return x.session.conn.LocalAddr()
}

func (x *interPacketConn) SetDeadline(t time.Time) error {
	if x.deadline == nil {
		if !t.IsZero() {
			x.deadline = time.AfterFunc(time.Until(t), func() { x.Close() })
		}
		return nil
	}

	if t.IsZero() {
		x.deadline.Stop()
	} else {
		x.deadline.Reset(time.Until(t))
	}
	return nil
}
func (x *interPacketConn) SetReadDeadline(t time.Time) error  { return x.SetDeadline(t) }
func (x *interPacketConn) SetWriteDeadline(t time.Time) error { return x.SetDeadline(t) }
