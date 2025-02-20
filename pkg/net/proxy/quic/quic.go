package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	ytls "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/quic-go/quic-go"
)

type Client struct {
	netapi.EmptyDispatch

	dialer netapi.Proxy

	session    quic.Connection
	underlying net.PacketConn

	tlsConfig *tls.Config

	packetConn *ConnectionPacketConn

	host   *net.UDPAddr
	natMap syncmap.SyncMap[uint64, *clientPacketConn]

	sessionUnix int64

	idg id.IDGenerator

	sessionMu sync.RWMutex
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *protocol.Quic, dd netapi.Proxy) (netapi.Proxy, error) {
	var host *net.UDPAddr = &net.UDPAddr{IP: net.IPv4zero}

	if config.GetHost() != "" {
		addr, err := netapi.ParseAddress("udp", config.GetHost())
		if err == nil {
			host, err = dialer.ResolveUDPAddr(context.TODO(), addr)
			if err != nil {
				return nil, err
			}
		}
	}

	tlsConfig := ytls.ParseTLSConfig(config.GetTls())
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}

	if register.IsBootstrap(dd) {
		dd = nil
	}

	c := &Client{
		dialer:    dd,
		tlsConfig: tlsConfig,
		host:      host,
	}

	return c, nil
}

func (c *Client) initSession(ctx context.Context) (quic.Connection, error) {
	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()

	if session != nil {
		select {
		case <-session.Context().Done():
		default:
			return session, nil
		}
	}

	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()

	if c.session != nil {
		select {
		case <-c.session.Context().Done():
		default:
			return c.session, nil
		}
	}

	if c.session != nil {
		_ = c.session.CloseWithError(0, "")
	}

	if c.underlying != nil {
		_ = c.underlying.Close()
	}

	var conn net.PacketConn
	var err error

	if c.dialer == nil {
		conn, err = dialer.ListenPacket(ctx, "udp", "")
	} else {
		conn, err = c.dialer.PacketConn(ctx, netapi.EmptyAddr)
	}
	if err != nil {
		return nil, err
	}

	tr := quic.Transport{
		Conn:               conn,
		ConnectionIDLength: 12,
	}

	config := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: time.Second * 15,
		MaxIdleTimeout:  time.Second * 40,
	}

	session, err = tr.Dial(ctx, c.host, c.tlsConfig, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	pconn := NewConnectionPacketConn(session)

	c.underlying = conn
	c.session = session
	c.sessionUnix = system.NowUnix()

	// Datagram
	c.packetConn = pconn
	go func() {
		defer session.CloseWithError(0, "")
		for {
			id, data, err := pconn.Receive(context.TODO())
			if err != nil {
				return
			}

			cchan, ok := c.natMap.Load(id)
			if !ok {
				continue
			}

			select {
			case <-session.Context().Done():
				return
			case <-cchan.ctx.Done():
			case cchan.msg <- data:
			}
		}
	}()

	return session, nil
}

func (c *Client) Close() error {
	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()

	var err error

	if c.dialer != nil {
		if er := c.dialer.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if session != nil {
		if er := session.CloseWithError(0, ""); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

func (c *Client) Conn(ctx context.Context, s netapi.Address) (net.Conn, error) {
	session, err := c.initSession(ctx)
	if err != nil {
		return nil, err
	}

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		_ = session.CloseWithError(0, "")
		return nil, err
	}

	return &interConn{
		Stream:  stream,
		session: session,
		time:    c.sessionUnix,
	}, nil
}

func (c *Client) PacketConn(ctx context.Context, host netapi.Address) (net.PacketConn, error) {
	_, err := c.initSession(ctx)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.TODO())

	cp := &clientPacketConn{
		c:             c,
		ctx:           ctx,
		cancel:        cancel,
		session:       c.packetConn,
		id:            c.idg.Generate(),
		msg:           make(chan *pool.Buffer, 100),
		writeDeadline: pipe.MakePipeDeadline(),
		readDeadline:  pipe.MakePipeDeadline(),
	}
	c.natMap.Store(cp.id, cp)

	return cp, nil
}

var _ net.Conn = (*interConn)(nil)

type interConn struct {
	quic.Stream
	session quic.Connection
	time    int64
}

func (c *interConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)

	if err != nil && err != io.EOF {
		qe, ok := err.(*quic.StreamError)
		if ok && qe.ErrorCode == quic.StreamErrorCode(quic.NoError) {
			err = io.EOF
		}
	}
	return
}

func (c *interConn) Write(p []byte) (n int, err error) {
	n, err = c.Stream.Write(p)
	if err != nil && err != io.EOF {
		qe, ok := err.(*quic.StreamError)
		if ok && qe.ErrorCode == quic.StreamErrorCode(quic.NoError) {
			err = io.EOF
		}
	}
	return
}

func (c *interConn) Close() error {
	err := c.Stream.Close()
	time.AfterFunc(time.Second*3, func() {
		// because quic must close read from peer, the close will not work to local read
		// so we assume the peer will close the stream first
		// otherwise, we cancel read manually
		c.Stream.CancelRead(quic.StreamErrorCode(quic.NoError))
	})
	return err
}

func (c *interConn) LocalAddr() net.Addr {
	return &QuicAddr{
		Addr: c.session.LocalAddr(),
		ID:   c.Stream.StreamID(),
		time: c.time,
	}
}

func (c *interConn) RemoteAddr() net.Addr {
	return &QuicAddr{
		Addr: c.session.RemoteAddr(),
		ID:   c.Stream.StreamID(),
		time: c.time,
	}
}

type QuicAddr struct {
	Addr net.Addr
	ID   quic.StreamID
	time int64
}

func (q *QuicAddr) String() string {
	if q.time == 0 {
		return fmt.Sprintf("quic://%d@%v", q.ID, q.Addr)
	}
	return fmt.Sprintf("quic://%d-%d@%v", q.time, q.ID, q.Addr)
}

func (q *QuicAddr) Network() string { return "udp" }

type clientPacketConn struct {
	ctx     context.Context
	c       *Client
	session *ConnectionPacketConn
	cancel  context.CancelFunc

	msg chan *pool.Buffer

	writeDeadline pipe.PipeDeadline
	readDeadline  pipe.PipeDeadline
	id            uint64
}

func (x *clientPacketConn) ReadFrom(p []byte) (n int, _ net.Addr, err error) {
	select {
	case <-x.session.Context().Done():
		return x.read(p, func() error {
			x.Close()
			return x.session.Context().Err()
		})
	case <-x.readDeadline.Wait():
		return x.read(p, func() error { return os.ErrDeadlineExceeded })
	case <-x.ctx.Done():
		return x.read(p, x.ctx.Err)
	case msg := <-x.msg:
		defer msg.Reset()

		n = copy(p, msg.Bytes())

		return n, x.session.conn.RemoteAddr(), nil
	}
}

func (x *clientPacketConn) read(p []byte, err func() error) (n int, _ net.Addr, _ error) {
	if len(x.msg) > 0 {
		select {
		case msg := <-x.msg:
			defer msg.Reset()

			n = copy(p, msg.Bytes())
			return n, x.session.conn.RemoteAddr(), nil
		default:
		}
	}

	return 0, nil, err()
}

func (x *clientPacketConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	select {
	case <-x.ctx.Done():
		return 0, io.ErrClosedPipe
	case <-x.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	case <-x.session.Context().Done():
		return 0, io.ErrClosedPipe
	default:
	}

	err = x.session.Write(p, x.id)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (x *clientPacketConn) Close() error {
	x.cancel()
	x.c.natMap.Delete(x.id)
	return nil
}

func (x *clientPacketConn) LocalAddr() net.Addr {
	return &QuicAddr{
		Addr: x.session.conn.LocalAddr(),
		ID:   quic.StreamID(x.id),
	}
}

func (x *clientPacketConn) SetDeadline(t time.Time) error {
	select {
	case <-x.ctx.Done():
		return io.EOF
	default:
	}

	_ = x.SetWriteDeadline(t)
	_ = x.SetReadDeadline(t)
	return nil
}

func (x *clientPacketConn) SetReadDeadline(t time.Time) error {
	x.readDeadline.Set(t)
	return nil
}

func (x *clientPacketConn) SetWriteDeadline(t time.Time) error {
	x.writeDeadline.Set(t)
	return nil
}
