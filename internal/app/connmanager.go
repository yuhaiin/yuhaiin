package app

import (
	context "context"
	"io"
	"log"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

var _ proxy.Proxy = (*ConnManager)(nil)
var _ ConnectionsServer = (*ConnManager)(nil)

type ConnManager struct {
	UnimplementedConnectionsServer
	conns    sync.Map
	download uint64
	upload   uint64
	idSeed   *idGenerater
	proxy    proxy.Proxy
}

func NewConnManager(p proxy.Proxy) *ConnManager {
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	c := &ConnManager{
		download: 0,
		upload:   0,

		idSeed: &idGenerater{},
		proxy:  p,
	}

	return c
}

func (c *ConnManager) SetProxy(p proxy.Proxy) {
	if p == nil {
		p = &proxy.DefaultProxy{}
	}

	c.proxy = p
}

var connRespName = reflect.TypeOf(ConnRespConnection{}).Name()

func (c *ConnManager) Conns(context.Context, *emptypb.Empty) (*ConnResp, error) {
	resp := &ConnResp{}
	c.conns.Range(func(key, value interface{}) bool {
		v := reflect.ValueOf(value)
		if v.Kind() != reflect.Ptr && v.Kind() != reflect.Interface {
			log.Println(v.Kind())
			return true
		}

		v = v.Elem()
		if v.Kind() != reflect.Struct {
			log.Println(v.Kind())
			return true
		}

		v = v.FieldByName(connRespName)
		if v.IsValid() {
			v, ok := v.Interface().(*ConnRespConnection)
			if ok {
				resp.Connections = append(resp.Connections, v)
			}
		}
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

		v := reflect.ValueOf(z)
		if v.IsNil() || !v.IsValid() {
			continue
		}
		cl := v.MethodByName("Close")
		if !cl.IsValid() {
			continue
		}

		_ = cl.Call([]reflect.Value{})
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

func (c *ConnManager) GetDownload() uint64 {
	return atomic.LoadUint64(&c.download)
}

func (c *ConnManager) GetUpload() uint64 {
	return atomic.LoadUint64(&c.upload)
}

func (c *ConnManager) add(i *conn) {
	c.conns.Store(i.Id, i)
}

func (c *ConnManager) addPacketConn(i *packetConn) {
	c.conns.Store(i.Id, i)
}

func (c *ConnManager) delete(id int64) {
	v, _ := c.conns.LoadAndDelete(id)

	vv := reflect.ValueOf(v)
	if vv.Kind() != reflect.Ptr && vv.Kind() != reflect.Interface {
		return
	}

	vv = vv.Elem()
	if vv.Kind() != reflect.Struct {
		return
	}

	logasfmt.Printf("close %s id: %v,addr: %v\n",
		vv.Type().Name(), vv.FieldByName("Id"), vv.FieldByName("Addr"))
}

func (c *ConnManager) newConn(addr string, x net.Conn) net.Conn {
	s := &conn{
		ConnRespConnection: &ConnRespConnection{
			Id:     c.idSeed.Generate(),
			Addr:   addr,
			Local:  x.LocalAddr().String(),
			Remote: x.RemoteAddr().String(),
		},
		Conn: x,
		cm:   c,
	}

	c.add(s)

	return s
}

func (c *ConnManager) newPacketConn(addr string, x net.PacketConn) net.PacketConn {
	if x == nil {
		return nil
	}
	s := &packetConn{
		ConnRespConnection: &ConnRespConnection{
			Id:     c.idSeed.Generate(),
			Addr:   addr,
			Local:  x.LocalAddr().String(),
			Remote: addr,
		},
		PacketConn: x,
		cm:         c,
	}

	c.addPacketConn(s)

	return s
}

func (c *ConnManager) Conn(host string) (net.Conn, error) {
	conn, err := c.proxy.Conn(host)
	if err != nil {
		return nil, err
	}

	_, ok := conn.(io.ReaderFrom)
	logasfmt.Println("app conn", reflect.TypeOf(conn), ok)
	return c.newConn(host, conn), nil
}

func (c *ConnManager) PacketConn(host string) (net.PacketConn, error) {
	conn, err := c.proxy.PacketConn(host)
	if err != nil {
		return nil, err
	}
	return c.newPacketConn(host, conn), nil
}

var _ net.Conn = (*conn)(nil)

type conn struct {
	net.Conn
	cm *ConnManager

	*ConnRespConnection
}

func (s *conn) Close() error {
	s.cm.delete(s.Id)
	return s.Conn.Close()
}

func (s *conn) Write(b []byte) (n int, err error) {
	n, err = s.Conn.Write(b)
	atomic.AddUint64(&s.cm.upload, uint64(n))
	return
}

func (s *conn) Read(b []byte) (n int, err error) {
	n, err = s.Conn.Read(b)
	atomic.AddUint64(&s.cm.download, uint64(n))
	return
}

func (s *conn) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(s.Conn, r)
	atomic.AddUint64(&s.cm.download, uint64(n))
	return n, err
}

func (s *conn) WriteTo(r io.Writer) (int64, error) {
	n, err := io.Copy(r, s.Conn)
	atomic.AddUint64(&s.cm.upload, uint64(n))
	return n, err
}

var _ net.PacketConn = (*packetConn)(nil)

type packetConn struct {
	net.PacketConn
	cm *ConnManager

	*ConnRespConnection
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
