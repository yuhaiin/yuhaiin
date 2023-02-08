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
	"os"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/quic-go/quic-go"
)

type Client struct {
	host *net.UDPAddr
	addr proxy.Address

	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	dialer      proxy.Proxy
	session     quic.Connection
	sessionLock sync.Mutex

	id      id.IDGenerator
	udpMap  map[uint64]chan packet
	udpLock sync.RWMutex
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

func (c *Client) initSession() error {
	c.sessionLock.Lock()
	defer c.sessionLock.Unlock()

	if c.session != nil {
		return nil
	}
	conn, err := c.dialer.PacketConn(c.addr)
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
			c.sessionLock.Lock()
			defer c.sessionLock.Unlock()
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

	c.udpLock.RLock()
	x, ok := c.udpMap[uint64(id)]
	if !ok {
		return fmt.Errorf("unknown udp id: %d, %v", id, b[:2])
	}

	x <- packet{
		data: b[2+len(addr):],
		addr: addr.Address(statistic.Type_udp),
	}
	c.udpLock.RUnlock()

	return nil
}

func (c *Client) Conn(s proxy.Address) (net.Conn, error) {
	if err := c.initSession(); err != nil {
		return nil, err
	}

	stream, err := c.session.OpenStreamSync(s.Context())
	if err != nil {
		return nil, err
	}

	return &interConn{
		Stream: stream,
		local:  c.session.LocalAddr(),
		remote: c.session.RemoteAddr(),
	}, nil
}

func (c *Client) PacketConn(host proxy.Address) (net.PacketConn, error) {
	if err := c.initSession(); err != nil {
		return nil, err
	}

	id := c.id.Generate()
	msgChan := make(chan packet, 30)

	c.udpLock.Lock()
	c.udpMap[id] = msgChan
	c.udpLock.Unlock()

	return &interPacketConn{
		c:                   c,
		session:             c.session,
		msgChan:             msgChan,
		id:                  uint16(id),
		resetDeadlineSignal: make(chan struct{}),
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

	resetDeadlineSignal chan struct{}
	deadline            time.Time
}

func (x *interPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
_resetDeadline:
	if x.closed {
		return 0, nil, net.ErrClosed
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if !x.deadline.IsZero() {
		ctx, cancel = context.WithDeadline(context.TODO(), x.deadline)
	} else {
		ctx, cancel = context.WithCancel(context.TODO())
	}

	select {
	case <-x.resetDeadlineSignal:
		cancel()
		goto _resetDeadline
	case <-ctx.Done():
		cancel()
		return 0, nil, os.ErrDeadlineExceeded
	case msg, ok := <-x.msgChan:
		log.Println("get data from msg chan", msg)
		cancel()
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n = copy(p, msg.data)

		return n, msg.addr, nil
	}
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
	x.c.udpLock.Lock()
	defer x.c.udpLock.Unlock()

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
	x.SetReadDeadline(t)
	x.SetWriteDeadline(t)
	return nil
}

func (x *interPacketConn) SetReadDeadline(t time.Time) error {
	x.deadline = t
	reset := x.resetDeadlineSignal
	x.resetDeadlineSignal = make(chan struct{})
	close(reset)
	return nil
}

func (x *interPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}
