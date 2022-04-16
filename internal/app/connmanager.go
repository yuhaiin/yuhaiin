package app

import (
	"context"
	"fmt"
	"io"
	"net"
	sync "sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

var _ proxy.Proxy = (*ConnManager)(nil)

type ConnManager struct {
	statistic.UnimplementedConnectionsServer

	idSeed        *idGenerater
	conns         syncmap.SyncMap[int64, staticConn]
	accountant    accountant
	proxy, direct proxy.Proxy
	mapper        func(string) MODE
}

func NewConnManager(conf *config.Config, p proxy.Proxy) *ConnManager {
	if p == nil {
		p = &proxy.Default{}
	}

	c := &ConnManager{
		idSeed: &idGenerater{},
		proxy:  p,
	}

	shunt := NewShunt(conf, WithProxy(c))

	conf.AddObserverAndExec(
		func(current, old *protoconfig.Setting) bool { return diffDNS(current.Dns.Local, old.Dns.Local) },
		func(current *protoconfig.Setting) {
			c.direct = direct.NewDirect(direct.WithLookup(getDNS(current.Dns.Local, nil).LookupIP))
		},
	)

	conf.AddObserverAndExec(
		func(current, old *protoconfig.Setting) bool { return current.Bypass.Enabled != old.Bypass.Enabled },
		func(current *protoconfig.Setting) {
			if !current.Bypass.Enabled {
				c.mapper = func(s string) MODE { return OTHERS }
			} else {
				c.mapper = shunt.Get
			}
		})

	return c
}

func (c *ConnManager) Conns(context.Context, *emptypb.Empty) (*statistic.ConnResp, error) {
	resp := &statistic.ConnResp{}
	c.conns.Range(func(key int64, v staticConn) bool {
		resp.Connections = append(resp.Connections, v.GetConnResp())
		return true
	})

	return resp, nil
}

func (c *ConnManager) CloseConn(_ context.Context, x *statistic.CloseConnsReq) (*emptypb.Empty, error) {
	for _, x := range x.Conns {
		if z, ok := c.conns.Load(x); ok {
			z.Close()
		}
	}
	return &emptypb.Empty{}, nil
}

func (c *ConnManager) Statistic(_ *emptypb.Empty, srv statistic.Connections_StatisticServer) error {
	logasfmt.Println("Start Send Flow Message to Client.")
	id := c.accountant.AddClient(srv.Send)
	<-srv.Context().Done()
	c.accountant.RemoveClient(id)
	logasfmt.Println("Client is Hidden, Close Stream.")
	return srv.Context().Err()
}

func (c *ConnManager) delete(id int64) {
	if z, ok := c.conns.LoadAndDelete(id); ok {
		logasfmt.Printf("close %v<%s[%v]>: %v, %s <-> %s\n",
			z.GetId(), z.Type(), z.GetMark(), z.GetAddr(), z.GetLocal(), z.GetRemote())
	}
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
			ConnRespConnection: &statistic.ConnRespConnection{
				Id:     c.idSeed.Generate(),
				Addr:   host,
				Mark:   mark.String(),
				Local:  con.LocalAddr().String(),
				Remote: con.RemoteAddr().String(),
			},
			Conn: con,
			cm:   c,
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
		cm:         c,
		ConnRespConnection: &statistic.ConnRespConnection{
			Addr:   host,
			Id:     c.idSeed.Generate(),
			Local:  con.LocalAddr().String(),
			Remote: host,
			Mark:   mark.String(),
		},
	}
	c.conns.Store(s.Id, s)
	return s, nil
}

type staticConn interface {
	io.Closer

	Type() string
	GetId() int64
	GetAddr() string
	GetLocal() string
	GetRemote() string
	GetMark() string
	GetConnResp() *statistic.ConnRespConnection
}

var _ staticConn = (*conn)(nil)

type conn struct {
	*preConn
}

func (s *conn) Type() string {
	return "TCP"
}

func (s *conn) GetConnResp() *statistic.ConnRespConnection {
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
	cm *ConnManager
	*statistic.ConnRespConnection
}

func (s *preConn) Close() error {
	s.cm.delete(s.Id)
	return s.Conn.Close()
}

func (s *preConn) Write(b []byte) (n int, err error) {
	n, err = s.Conn.Write(b)
	s.cm.accountant.AddUpload(uint64(n))
	return
}

func (s *preConn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	s.cm.accountant.AddDownload(uint64(n))
	return
}

var _ net.PacketConn = (*packetConn)(nil)
var _ staticConn = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn
	cm *ConnManager

	*statistic.ConnRespConnection
}

func (s *packetConn) Type() string {
	return "UDP"
}

func (s *packetConn) GetConnResp() *statistic.ConnRespConnection {
	return s.ConnRespConnection
}

func (s *packetConn) Close() error {
	s.cm.delete(s.Id)
	return s.PacketConn.Close()
}

func (s *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	n, err = s.PacketConn.WriteTo(p, addr)
	s.cm.accountant.AddUpload(uint64(n))
	return
}

func (s *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	s.cm.accountant.AddDownload(uint64(n))
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
		return proxy.NewErrProxy(fmt.Errorf("split host [%s] failed: %v", host, err)), MODE("UNKNOWN")
	}

	mark = m.mapper(hostname)

	switch mark {
	case BLOCK:
		p = proxy.NewErrProxy(fmt.Errorf("BLOCK: %v", host))
	case DIRECT:
		p = m.direct
	default:
		p = m.proxy
	}

	return
}

type accountant struct {
	download, upload uint64

	clientCount int64

	started chan bool

	ig      idGenerater
	clients syncmap.SyncMap[int64, func(*statistic.RateResp) error]
	lock    sync.Mutex
}

func (c *accountant) AddDownload(n uint64) {
	atomic.AddUint64(&c.download, uint64(n))
}

func (c *accountant) AddUpload(n uint64) {
	atomic.AddUint64(&c.upload, uint64(n))
}

func (c *accountant) start() {
	c.lock.Lock()
	defer c.lock.Unlock()
	atomic.AddInt64(&c.clientCount, 1)
	if c.started != nil {
		select {
		case <-c.started:
		default:
			return
		}
	}

	c.started = make(chan bool)

	go func() {
		tmpD, tmpU := atomic.LoadUint64(&c.download), atomic.LoadUint64(&c.upload)

		for {
			select {
			case <-time.After(time.Second):
			case _, ok := <-c.started:
				if !ok {
					logasfmt.Println("accountant stopped")
					return
				}
			}

			d, u := atomic.LoadUint64(&c.download), atomic.LoadUint64(&c.upload)

			c.clients.Range(func(key int64, value func(*statistic.RateResp) error) bool {
				err := value(&statistic.RateResp{
					Download:     utils.ReducedUnitToString(float64(d)),
					Upload:       utils.ReducedUnitToString(float64(u)),
					DownloadRate: utils.ReducedUnitToString(float64(d-tmpD)) + "/S",
					UploadRate:   utils.ReducedUnitToString(float64(u-tmpU)) + "/S",
				})
				if err != nil {
					logasfmt.Println("accountant client error:", err)
				}
				return true
			})

			tmpD, tmpU = d, u
		}
	}()
}

func (c *accountant) stop() {
	c.lock.Lock()
	defer c.lock.Unlock()
	atomic.AddInt64(&c.clientCount, -1)
	if atomic.LoadInt64(&c.clientCount) > 0 {
		return
	}

	logasfmt.Println("accountant stopping")

	if c.started != nil {
		close(c.started)
		c.started = nil
	}
}

func (c *accountant) AddClient(f func(*statistic.RateResp) error) (id int64) {
	id = c.ig.Generate()
	c.clients.Store(id, f)
	c.start()
	return
}

func (c *accountant) RemoveClient(id int64) {
	c.clients.Delete(id)
	c.stop()
}
