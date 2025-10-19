package yuubinsya

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type client struct {
	netapi.Proxy

	hash []byte

	overTCP  bool
	coalesce bool

	pingCache syncmap.SyncMap[string, *pingConn]
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *node.Yuubinsya, dialer netapi.Proxy) (netapi.Proxy, error) {
	hash := Salt([]byte(config.GetPassword()))
	c := &client{
		Proxy:    dialer,
		hash:     hash,
		overTCP:  config.GetUdpOverStream(),
		coalesce: config.GetUdpCoalesce(),
	}

	return c, nil
}

func (c *client) Close() error {
	for k := range c.pingCache.Range {
		conn, ok := c.pingCache.LoadAndDelete(k)
		if ok {
			_ = conn.Close()
		}
	}

	return c.Proxy.Close()
}

func (c *client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	buf := pool.NewBufferSize(1024)
	defer buf.Reset()

	EncodeHeader(c.hash, Header{Protocol: TCP, Addr: addr}, buf)

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}

func (c *client) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	if !c.overTCP {
		packet, err := c.Proxy.PacketConn(ctx, addr)
		if err != nil {
			return nil, err
		}

		return NewAuthPacketConn(packet).WithRealTarget(addr).WithPassword(c.hash), nil
	}

	conn, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	pc := newPacketConn(pool.NewBufioConnSize(conn, configuration.UDPBufferSize.Load()),
		c.hash, c.coalesce)

	store := netapi.GetContext(ctx)

	migrate, err := pc.Handshake(store.GetUDPMigrateID())
	if err != nil {
		_ = pc.Close()
		return nil, err
	}

	store.SetUDPMigrateID(migrate)

	return pc, nil
}

func (c *client) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	start := time.Now()

	var b [8]byte
	conn, ok, err := c.pingCache.LoadOrCreate(addr.Hostname(), func() (*pingConn, error) {
		conn, err := c.Proxy.Conn(ctx, addr)
		if err != nil {
			return nil, err
		}

		buf := pool.NewBufferSize(1024)
		defer buf.Reset()

		EncodeHeader(c.hash, Header{Protocol: Ping, Addr: addr}, buf)

		pc := newPing(c, conn, addr.Hostname())

		b, err = ping(pc, buf.Bytes())
		if err != nil {
			return nil, err
		}

		return pc, nil
	})
	if err != nil {
		return 0, err
	}

	if !ok {
		if b == [8]byte{255, 255, 255, 255, 255, 255, 255, 255} {
			return 0, fmt.Errorf("ping failed")
		}

		return uint64(time.Since(start)), nil
	}

	conn.ResetTimer()

	b, err = ping(conn, b[:])
	if err != nil {
		return 0, err
	}

	if b == [8]byte{255, 255, 255, 255, 255, 255, 255, 255} {
		return 0, fmt.Errorf("ping failed")
	}

	return uint64(time.Since(start)), nil
}

func ping(conn *pingConn, data []byte) (b [8]byte, err error) {
	// only one request in flight
	conn.mu.Lock()
	defer conn.mu.Unlock()

	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()

	err = conn.SetWriteDeadline(time.Now().Add(time.Second * 10))
	if err != nil {
		return [8]byte{}, err
	}

	_, err = conn.Write(data)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return [8]byte{}, err
	}

	err = conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	if err != nil {
		return [8]byte{}, err
	}

	_, err = conn.Read(b[:])
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return [8]byte{}, err
	}

	return
}

type pingConn struct {
	c *client
	net.Conn
	key   string
	timer *time.Timer
	mu    sync.Mutex
}

func newPing(c *client, conn net.Conn, key string) *pingConn {
	pc := &pingConn{
		c:    c,
		Conn: conn,
		key:  key,
	}

	pc.timer = time.AfterFunc(time.Second*30, func() {
		if err := pc.Close(); err != nil {
			log.Warn("close ping conn failed", "err", err)
		}
	})

	return pc
}

func (p *pingConn) ResetTimer() {
	if p.timer != nil {
		p.timer.Reset(time.Second * 30)
	}
}

func (p *pingConn) Close() error {
	if p.timer != nil {
		p.timer.Stop()
	}

	p.c.pingCache.Delete(p.key)
	return p.Conn.Close()
}
