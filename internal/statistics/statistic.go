package statistics

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	grpcsts "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type Statistics interface {
	AddConn(_ net.Conn, host proxy.Address) net.Conn
	AddPacketConn(_ net.PacketConn, host proxy.Address) net.PacketConn
	grpcsts.ConnectionsServer
	io.Closer
}

var _ Statistics = (*counter)(nil)

type counter struct {
	grpcsts.UnimplementedConnectionsServer

	accountant

	idSeed IDGenerator
	conns  syncmap.SyncMap[int64, connection]
}

func NewStatistics() Statistics { return &counter{} }

func (c *counter) Conns(context.Context, *emptypb.Empty) (*statistic.ConnResp, error) {
	resp := &statistic.ConnResp{}
	c.conns.Range(func(key int64, v connection) bool {
		resp.Connections = append(resp.Connections, v.Info())
		return true
	})

	return resp, nil
}

func (c *counter) CloseConn(_ context.Context, x *statistic.CloseConnsReq) (*emptypb.Empty, error) {
	for _, x := range x.Conns {
		if z, ok := c.conns.Load(x); ok {
			z.Close()
		}
	}
	return &emptypb.Empty{}, nil
}

func (c *counter) Close() error {
	c.conns.Range(func(key int64, v connection) bool {
		v.Close()
		return true
	})

	return nil
}

func (c *counter) Statistic(_ *emptypb.Empty, srv grpcsts.Connections_StatisticServer) error {
	log.Infoln("Start Send Flow Message to Client.")
	id := c.accountant.AddClient(srv.Send)
	<-srv.Context().Done()
	c.accountant.RemoveClient(id)
	log.Infoln("Client is Hidden, Close Stream.")
	return srv.Context().Err()
}

func (c *counter) delete(id int64) {
	if z, ok := c.conns.LoadAndDelete(id); ok {
		log.Debugln("close", c.cString(z))
	}
}

func (c *counter) storeConnection(o connection) {
	log.Debugf(c.cString(o))
	c.conns.Store(o.GetId(), o)
}

func (c *counter) cString(o connection) (s string) {
	if log.IsOutput(config.Logcat_debug) {
		s = fmt.Sprintf("%v| <%s>: %v(%s), %s <-> %s",
			o.GetId(), o.GetType(), o.GetAddr(), getExtra(o), o.GetLocal(), o.GetRemote())
	}
	return
}

func getExtra(o connection) string {
	str := strings.Builder{}

	for k, v := range o.GetExtra() {
		str.WriteString(fmt.Sprintf("%s: %s,", k, v))
	}

	return str.String()
}

func extraMap(addr proxy.Address) map[string]string {
	r := make(map[string]string)
	addr.RangeMark(func(k, v any) bool {
		kk, ok := k.(string)
		if !ok {
			return true
		}

		vv, ok := v.(string)
		if !ok {
			return true
		}

		r[kk] = vv
		return true
	})

	return r
}

func (c *counter) AddPacketConn(con net.PacketConn, addr proxy.Address) net.PacketConn {
	z := &packetConn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   addr.String(),
			Local:  con.LocalAddr().String(),
			Remote: addr.String(),
			Type:   fmt.Sprintf("UDP(%s)", con.LocalAddr().Network()),
			Extra:  extraMap(addr),
		},
		PacketConn: con,
		manager:    c,
	}

	c.storeConnection(z)
	return z
}

func (c *counter) AddConn(con net.Conn, addr proxy.Address) net.Conn {
	z := &conn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   addr.String(),
			Local:  con.LocalAddr().String(),
			Remote: con.RemoteAddr().String(),
			Type:   fmt.Sprintf("TCP(%s)", con.LocalAddr().Network()),
			Extra:  extraMap(addr),
		},
		Conn:    con,
		manager: c,
	}

	c.storeConnection(z)
	return z
}
