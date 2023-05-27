package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/quic-go/quic-go"
)

type Client struct {
	proxy.EmptyDispatch
	host *net.UDPAddr
	addr proxy.Address

	tlsConfig  *tls.Config
	quicConfig *quic.Config
	dialer     proxy.Proxy
	session    quic.Connection
	sessionMu  sync.Mutex

	id     id.IDGenerator
	udpMap map[uint64]chan packet
	udpMu  sync.RWMutex
}

func New(config *protocol.Protocol_Quic) protocol.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {
		uaddr, err := net.ResolveUDPAddr("udp", config.Quic.Host)
		if err != nil {
			return nil, err
		}

		c := &Client{
			host:      uaddr,
			dialer:    dialer,
			tlsConfig: protocol.ParseTLSConfig(config.Quic.Tls),
			quicConfig: &quic.Config{
				MaxIdleTimeout:  20 * time.Second,
				KeepAlivePeriod: 20 * time.Second * 2 / 5,
				EnableDatagrams: true,
			},

			udpMap: make(map[uint64]chan packet),
		}

		if c.tlsConfig == nil {
			c.tlsConfig = &tls.Config{}
		}

		addr, err := proxy.ParseAddress(statistic.Type_udp, config.Quic.Host)
		if err != nil {
			return nil, err
		}

		c.addr = addr

		return c, nil
	}
}

func (c *Client) initSession(ctx context.Context) error {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()

	if c.session != nil {
		return nil
	}
	conn, err := c.dialer.PacketConn(ctx, c.addr)
	if err != nil {
		return err
	}
	session, err := quic.DialEarly(conn, c.host, c.host.String(), c.tlsConfig, c.quicConfig)
	if err != nil {
		return err
	}
	go func() {
		select {
		case <-session.Context().Done():
			c.sessionMu.Lock()
			defer c.sessionMu.Unlock()
			session.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
			conn.Close()
			log.Println("session closed")
			c.session = nil
		}
	}()

	go func() {
		for {
			b, err := session.ReceiveMessage()
			if err != nil {
				break
			}

			if err = c.handleDatagrams(b); err != nil {
				log.Println("handle datagrams failed:", err)
			}
		}
	}()

	c.session = session
	return nil
}

func (c *Client) handleDatagrams(b []byte) error {
	if len(b) <= 5 {
		return fmt.Errorf("invalid data")
	}

	id := binary.BigEndian.Uint16(b[:2])
	addr, err := s5c.ResolveAddr(bytes.NewBuffer(b[2:]))
	if err != nil {
		return err
	}

	c.udpMu.RLock()
	x, ok := c.udpMap[uint64(id)]
	if !ok {
		return fmt.Errorf("unknown udp id: %d, %v", id, b[:2])
	}

	x <- packet{
		data: b[2+len(addr):],
		addr: addr.Address(statistic.Type_udp),
	}
	c.udpMu.RUnlock()

	return nil
}

func (c *Client) Conn(ctx context.Context, s proxy.Address) (net.Conn, error) {
	if err := c.initSession(ctx); err != nil {
		return nil, err
	}

	stream, err := c.session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	return &interConn{
		Stream: stream,
		local:  c.session.LocalAddr(),
		remote: c.session.RemoteAddr(),
	}, nil
}

func (c *Client) PacketConn(ctx context.Context, host proxy.Address) (net.PacketConn, error) {
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
		session: c.session,
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
		errors.Join(err, er)
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
	session quic.Connection
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

	ad, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, err
	}
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	binary.Write(buf, binary.BigEndian, x.id)
	s5c.ParseAddrWriter(ad, buf)
	buf.Write(p)

	if err = x.session.SendMessage(buf.Bytes()); err != nil {
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
	return x.session.LocalAddr()
}

func (x *interPacketConn) SetDeadline(t time.Time) error {
	if x.deadline == nil {
		if !t.IsZero() {
			x.deadline = time.AfterFunc(t.Sub(time.Now()), func() { x.Close() })
		}
		return nil
	}

	if t.IsZero() {
		x.deadline.Stop()
	} else {
		x.deadline.Reset(t.Sub(time.Now()))
	}
	return nil
}
func (x *interPacketConn) SetReadDeadline(t time.Time) error  { return x.SetDeadline(t) }
func (x *interPacketConn) SetWriteDeadline(t time.Time) error { return x.SetDeadline(t) }
