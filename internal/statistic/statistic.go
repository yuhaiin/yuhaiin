package statistic

import (
	"context"
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type conns interface {
	AddConn(_ net.Conn, host string, _ MODE) net.Conn
	AddPacketConn(_ net.PacketConn, host string, _ MODE) net.PacketConn
}

var _ conns = (*counter)(nil)

type counter struct {
	statistic.UnimplementedConnectionsServer

	accountant

	idSeed idGenerater
	conns  syncmap.SyncMap[int64, connection]
}

func NewStatistic() *counter { return &counter{} }

func (c *counter) Conns(context.Context, *emptypb.Empty) (*statistic.ConnResp, error) {
	resp := &statistic.ConnResp{}
	c.conns.Range(func(key int64, v connection) bool {
		resp.Connections = append(resp.Connections, v.GetStatistic())
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

func (c *counter) Statistic(_ *emptypb.Empty, srv statistic.Connections_StatisticServer) error {
	log.Println("Start Send Flow Message to Client.")
	id := c.accountant.AddClient(srv.Send)
	<-srv.Context().Done()
	c.accountant.RemoveClient(id)
	log.Println("Client is Hidden, Close Stream.")
	return srv.Context().Err()
}

func (c *counter) delete(id int64) {
	if z, ok := c.conns.LoadAndDelete(id); ok {
		log.Printf("close %v| <%s[%v]>: %v, %s <-> %s\n",
			z.GetId(), z.GetType(), z.GetMark(), z.GetAddr(), z.GetLocal(), z.GetRemote())
	}
}

func (c *counter) storeConnection(o connection) {
	log.Printf("%v| <%s[%v]>: %v, %s <-> %s\n",
		o.GetId(), o.GetType(), o.GetMark(), o.GetAddr(), o.GetLocal(), o.GetRemote())
	c.conns.Store(o.GetId(), o)
}
