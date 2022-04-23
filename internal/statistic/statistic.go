package statistic

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
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
	dialer *dialer
	conns  syncmap.SyncMap[int64, connection]
	shunt  *Shunt
}

func NewStatistic(dialer proxy.Proxy) *Statistic {
	if dialer == nil {
		dialer = &proxy.Default{}
	}

	c := &Statistic{dialer: newDialer(dialer)}

	c.shunt = newShunt(c)
	return c
}

func (c *Statistic) Update(s *protoconfig.Setting) {
	c.dialer.Update(s)
	c.shunt.Update(s)
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
	logasfmt.Println("Start Send Flow Message to Client.")
	id := c.accountant.AddClient(srv.Send)
	<-srv.Context().Done()
	c.accountant.RemoveClient(id)
	logasfmt.Println("Client is Hidden, Close Stream.")
	return srv.Context().Err()
}

func (c *Statistic) delete(id int64) {
	if z, ok := c.conns.LoadAndDelete(id); ok {
		logasfmt.Printf("close %v| <%s[%v]>: %v, %s <-> %s\n",
			z.GetId(), z.GetType(), z.GetMark(), z.GetAddr(), z.GetLocal(), z.GetRemote())
	}
}

func (c *Statistic) Conn(host string) (net.Conn, error) {
	mark := c.shunt.Get(host)

	con, err := c.dialer.dial(mark).Conn(host)
	if err != nil {
		return nil, err
	}

	s := &conn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   host,
			Mark:   mark.String(),
			Local:  con.LocalAddr().String(),
			Remote: con.RemoteAddr().String(),
			Type:   "Stream",
		},
		Conn:    con,
		manager: c,
	}
	c.storeConnection(s)
	return s, nil
}

func (c *Statistic) PacketConn(host string) (net.PacketConn, error) {
	mark := c.shunt.Get(host)

	con, err := c.dialer.dial(mark).PacketConn(host)
	if err != nil {
		return nil, err
	}

	s := &packetConn{
		PacketConn: con,
		manager:    c,
		Connection: &statistic.Connection{
			Addr:   host,
			Id:     c.idSeed.Generate(),
			Local:  con.LocalAddr().String(),
			Remote: host,
			Mark:   mark.String(),
			Type:   "Packet",
		},
	}
	c.storeConnection(s)
	return s, nil
}

func (c *Statistic) storeConnection(o connection) {
	logasfmt.Printf("%v| <%s[%v]>: %v, %s <-> %s\n",
		o.GetId(), o.GetType(), o.GetMark(), o.GetAddr(), o.GetLocal(), o.GetRemote())
	c.conns.Store(o.GetId(), o)
}
