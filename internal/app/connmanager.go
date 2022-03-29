package app

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

var _ proxy.Proxy = (*ConnManager)(nil)
var _ ConnectionsServer = (*ConnManager)(nil)

type ConnManager struct {
	UnimplementedConnectionsServer

	idSeed           *idGenerater
	conns            syncmap.SyncMap[int64, staticConn]
	download, upload uint64
	proxy, direct    proxy.Proxy
	mapper           func(string) MODE
}

func NewConnManager(conf *config.Config, p proxy.Proxy) (*ConnManager, error) {
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	c := &ConnManager{
		download: 0,
		upload:   0,
		idSeed:   &idGenerater{},
		proxy:    p,
	}

	shunt, err := NewShunt(conf, WithProxy(c))
	if err != nil {
		return nil, fmt.Errorf("create shunt failed: %v, disable bypass.\n", err)
	}

	conf.AddObserverAndExec(
		func(current, old *config.Setting) bool { return diffDNS(current.Dns.Local, old.Dns.Local) },
		func(current *config.Setting) {
			c.direct = direct.NewDirect(direct.WithLookup(getDNS(current.Dns.Local, nil).LookupIP))
		},
	)

	conf.AddObserverAndExec(
		func(current, old *config.Setting) bool { return current.Bypass.Enabled != old.Bypass.Enabled },
		func(current *config.Setting) {
			if !current.Bypass.Enabled {
				c.mapper = func(s string) MODE { return OTHERS }
			} else {
				c.mapper = shunt.Get
			}
		})

	return c, nil
}

func (c *ConnManager) Conns(context.Context, *emptypb.Empty) (*ConnResp, error) {
	resp := &ConnResp{}
	c.conns.Range(func(key int64, v staticConn) bool {
		resp.Connections = append(resp.Connections, v.GetConnResp())
		return true
	})

	return resp, nil
}

func (c *ConnManager) CloseConn(_ context.Context, x *CloseConnsReq) (*emptypb.Empty, error) {
	for _, x := range x.Conns {
		z, ok := c.conns.Load(x)
		if !ok {
			return &emptypb.Empty{}, nil
		}
		z.Close()
	}
	return &emptypb.Empty{}, nil
}

func (c *ConnManager) Statistic(_ *emptypb.Empty, srv Connections_StatisticServer) error {
	logasfmt.Println("Start Send Flow Message to Client.")
	da, ua := atomic.LoadUint64(&c.download), atomic.LoadUint64(&c.upload)
	doa, uoa := da, ua
	ctx := srv.Context()
	for {
		doa, uoa = da, ua
		da, ua = atomic.LoadUint64(&c.download), atomic.LoadUint64(&c.upload)

		err := srv.Send(&RateResp{
			Download:     utils.ReducedUnitStr(float64(da)),
			Upload:       utils.ReducedUnitStr(float64(ua)),
			DownloadRate: utils.ReducedUnitStr(float64(da-doa)) + "/S",
			UploadRate:   utils.ReducedUnitStr(float64(ua-uoa)) + "/S",
		})
		if err != nil {
			log.Println(err)
		}

		select {
		case <-ctx.Done():
			logasfmt.Println("Client is Hidden, Close Stream.")
			return ctx.Err()
		case <-time.After(time.Second):
			continue
		}
	}
}

func (c *ConnManager) delete(id int64) {
	z, ok := c.conns.LoadAndDelete(id)
	if !ok {
		return
	}

	logasfmt.Printf("close %v<%s[%v]>: %v, %s <-> %s\n",
		z.GetId(), z.Type(), z.Mark(), z.GetAddr(), z.GetLocal(), z.GetRemote())
}

func (c *ConnManager) Conn(host string) (net.Conn, error) {
	p, mark := c.marry(host)

	logasfmt.Printf("[%s] -> %v\n", host, mark)

	con, err := p.Conn(host)
	if err != nil {
		return nil, err
	}

	s := &conn{
		preConn: &preConn{
			ConnRespConnection: &ConnRespConnection{
				Id:     c.idSeed.Generate(),
				Addr:   host,
				Local:  con.LocalAddr().String(),
				Remote: con.RemoteAddr().String(),
			},
			Conn: con,
			cm:   c,
			mark: mark,
		},
	}
	c.conns.Store(s.Id, s)
	return s, nil
}

func (c *ConnManager) PacketConn(host string) (net.PacketConn, error) {
	p, mark := c.marry(host)

	logasfmt.Printf("[%s] -> %v\n", host, mark)

	con, err := p.PacketConn(host)
	if err != nil {
		return nil, err
	}

	s := &packetConn{
		PacketConn: con,
		mark:       mark,
		cm:         c,
		ConnRespConnection: &ConnRespConnection{
			Addr:   host,
			Id:     c.idSeed.Generate(),
			Local:  con.LocalAddr().String(),
			Remote: host,
		},
	}
	c.conns.Store(s.Id, s)
	return s, nil
}

type staticConn interface {
	io.Closer

	Mark() MODE

	Type() string
	GetId() int64
	GetAddr() string
	GetLocal() string
	GetRemote() string
	GetConnResp() *ConnRespConnection
}

var _ staticConn = (*conn)(nil)

type conn struct {
	*preConn
}

func (s *conn) Type() string {
	return "TCP"
}

func (s *conn) Mark() MODE {
	return s.mark
}

func (s *conn) GetConnResp() *ConnRespConnection {
	return s.ConnRespConnection
}

func (s *conn) ReadFrom(r io.Reader) (resp int64, _ error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)
	return io.CopyBuffer(s.preConn, r, buf)
}

func (s *conn) WriteTo(w io.Writer) (resp int64, _ error) {
	buf := utils.GetBytes(2048)
	defer utils.PutBytes(buf)
	return io.CopyBuffer(w, s.preConn, buf)
}

var _ net.Conn = (*preConn)(nil)

type preConn struct {
	net.Conn
	cm   *ConnManager
	mark MODE
	*ConnRespConnection
}

func (s *preConn) Close() error {
	s.cm.delete(s.Id)
	return s.Conn.Close()
}

func (s *preConn) Write(b []byte) (n int, err error) {
	n, err = s.Conn.Write(b)
	atomic.AddUint64(&s.cm.upload, uint64(n))
	return
}

func (s *preConn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	atomic.AddUint64(&s.cm.download, uint64(n))
	return
}

var _ net.PacketConn = (*packetConn)(nil)
var _ staticConn = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn
	cm   *ConnManager
	mark MODE

	*ConnRespConnection
}

func (s *packetConn) Type() string {
	return "UDP"
}

func (s *packetConn) Mark() MODE {
	return s.mark
}

func (s *packetConn) GetConnResp() *ConnRespConnection {
	return s.ConnRespConnection
}

func (s *packetConn) Close() error {
	s.cm.delete(s.Id)
	return s.PacketConn.Close()
}

func (s *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = s.PacketConn.WriteTo(p, addr)
	atomic.AddUint64(&s.cm.upload, uint64(n))
	return
}

func (s *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	atomic.AddUint64(&s.cm.download, uint64(n))
	return
}

type idGenerater struct {
	node int64
}

func (i *idGenerater) Generate() (id int64) {
	return atomic.AddInt64(&i.node, 1)
}

func (m *ConnManager) marry(host string) (p proxy.Proxy, mark MODE) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return newErrProxy(fmt.Errorf("split host [%s] failed: %v", host, err)), MODE(-1)
	}

	mark = m.mapper(hostname)

	switch mark {
	case BLOCK:
		p = newErrProxy(fmt.Errorf("BLOCK: %v", host))
	case DIRECT:
		p = m.direct
	default:
		p = m.proxy
	}

	return
}

type errProxy struct {
	err error
}

func newErrProxy(err error) proxy.Proxy {
	return &errProxy{err: err}
}

func (e *errProxy) Conn(string) (net.Conn, error) {
	return nil, e.err
}

func (e *errProxy) PacketConn(string) (net.PacketConn, error) {
	return nil, e.err
}
