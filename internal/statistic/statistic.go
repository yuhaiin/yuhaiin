package statistic

import (
	"context"
	"errors"
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

var _ proxy.Proxy = (*Statistic)(nil)

type Statistic struct {
	statistic.UnimplementedConnectionsServer

	accountant

	idSeed idGenerater
	conns  syncmap.SyncMap[int64, connection]
	shunt  *Shunt

	remoteResolver *remoteResolver
	localResolver  *localResolver

	dial func(MODE) proxy.Proxy
}

func NewStatistic(dialer proxy.Proxy) *Statistic {
	if dialer == nil {
		dialer = &proxy.Default{}
	}

	c := &Statistic{}

	c.remoteResolver = newRemoteResolver(&resolverProxy{c})
	c.localResolver = newLocalResolver(&directProxy{c})
	c.shunt = newShunt(c.remoteResolver)

	direct := direct.NewDirect(direct.WithLookup(c.localResolver))
	block := proxy.NewErrProxy(errors.New("blocked"))
	c.dial = func(m MODE) proxy.Proxy {
		switch m {
		case DIRECT:
			return direct
		case BLOCK:
			return block
		}
		return dialer
	}

	return c
}

func (c *Statistic) Update(s *protoconfig.Setting) {
	c.shunt.Update(s)
	c.localResolver.Update(s)
	c.remoteResolver.Update(s)
}

func (c *Statistic) Conns(context.Context, *emptypb.Empty) (*statistic.ConnResp, error) {
	resp := &statistic.ConnResp{}
	c.conns.Range(func(key int64, v connection) bool {
		resp.Connections = append(resp.Connections, v.GetStatistic())
		return true
	})

	return resp, nil
}

func (c *Statistic) CloseConn(_ context.Context, x *statistic.CloseConnsReq) (*emptypb.Empty, error) {
	for _, x := range x.Conns {
		if z, ok := c.conns.Load(x); ok {
			z.Close()
		}
	}
	return &emptypb.Empty{}, nil
}

func (c *Statistic) Statistic(_ *emptypb.Empty, srv statistic.Connections_StatisticServer) error {
	log.Println("Start Send Flow Message to Client.")
	id := c.accountant.AddClient(srv.Send)
	<-srv.Context().Done()
	c.accountant.RemoveClient(id)
	log.Println("Client is Hidden, Close Stream.")
	return srv.Context().Err()
}

func (c *Statistic) delete(id int64) {
	if z, ok := c.conns.LoadAndDelete(id); ok {
		log.Printf("close %v| <%s[%v]>: %v, %s <-> %s\n",
			z.GetId(), z.GetType(), z.GetMark(), z.GetAddr(), z.GetLocal(), z.GetRemote())
	}
}

func (c *Statistic) Conn(host string) (net.Conn, error) {
	mark := c.shunt.Get(host)
	con, err := c.dial(mark).Conn(host)
	if err != nil {
		return nil, err
	}
	return c.addConn(con, host, mark), nil
}

func (c *Statistic) addConn(con net.Conn, host string, mark MODE) net.Conn {
	if con == nil {
		return nil
	}

	s := &conn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   host,
			Mark:   mark.String(),
			Local:  con.LocalAddr().String(),
			Remote: con.RemoteAddr().String(),
			Type:   con.LocalAddr().Network(),
		},
		Conn:    con,
		manager: c,
	}
	c.storeConnection(s)
	return s
}

func (c *Statistic) PacketConn(host string) (net.PacketConn, error) {
	mark := c.shunt.Get(host)
	con, err := c.dial(mark).PacketConn(host)
	if err != nil {
		return nil, err
	}
	return c.addPacketConn(con, host, mark), nil
}

func (c *Statistic) addPacketConn(con net.PacketConn, host string, mark MODE) net.PacketConn {
	s := &packetConn{
		PacketConn: con,
		manager:    c,
		Connection: &statistic.Connection{
			Addr:   host,
			Id:     c.idSeed.Generate(),
			Local:  con.LocalAddr().String(),
			Remote: host,
			Mark:   mark.String(),
			Type:   con.LocalAddr().Network(),
		},
	}
	c.storeConnection(s)
	return s
}

func (c *Statistic) storeConnection(o connection) {
	log.Printf("%v| <%s[%v]>: %v, %s <-> %s\n",
		o.GetId(), o.GetType(), o.GetMark(), o.GetAddr(), o.GetLocal(), o.GetRemote())
	c.conns.Store(o.GetId(), o)
}

type resolverProxy struct{ *Statistic }

func (c *resolverProxy) mark() MODE {
	if c.remoteResolver != nil && c.remoteResolver.IsProxy() {
		return PROXY
	}

	return DIRECT
}

func (c *resolverProxy) Conn(host string) (net.Conn, error) {
	con, err := c.dial(c.mark()).Conn(host)
	if err != nil {
		return nil, err
	}
	return c.addConn(con, host, c.mark()), nil
}

func (c *resolverProxy) PacketConn(host string) (net.PacketConn, error) {
	con, err := c.dial(c.mark()).PacketConn(host)
	if err != nil {
		return nil, err
	}
	return c.addPacketConn(con, host, c.mark()), nil
}

type directProxy struct{ *Statistic }

func (d *directProxy) Conn(host string) (net.Conn, error) {
	conn, err := direct.Default.Conn(host)
	if err != nil {
		return nil, err
	}

	return d.addConn(conn, host, DIRECT), nil
}

func (d *directProxy) PacketConn(host string) (net.PacketConn, error) {
	con, err := direct.Default.PacketConn(host)
	if err != nil {
		return nil, err
	}

	return d.addPacketConn(con, host, DIRECT), nil
}
