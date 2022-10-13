package statistics

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/internal/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	grpcsts "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type Statistics interface {
	grpcsts.ConnectionsServer
	io.Closer
	proxy.Proxy
}

var _ Statistics = (*counter)(nil)

type counter struct {
	grpcsts.UnimplementedConnectionsServer

	accountant

	idSeed IDGenerator
	conns  syncmap.SyncMap[int64, connection]

	dialer proxy.Proxy
}

func NewStatistics(dialer proxy.Proxy) Statistics {
	if dialer == nil {
		dialer = direct.Default
	}
	return &counter{dialer: dialer}
}

func (c *counter) SetDialer(d proxy.Proxy) { c.dialer = d }

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
	if log.IsOutput(protolog.LogLevel_debug) {
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

func getAddr(addr proxy.Address) string {
	z, ok := addr.Value(shunt.DOMAIN_MARK_KEY{})
	if ok {
		s, ok := getString(z)
		if ok {
			return s
		}
	}

	return addr.String()
}

func extraMap(addr proxy.Address) map[string]string {
	r := make(map[string]string)
	addr.RangeValue(func(k, v any) bool {
		kk, ok := getString(k)
		if !ok {
			return true
		}

		vv, ok := getString(v)
		if !ok {
			return true
		}

		r[kk] = vv
		return true
	})

	return r
}

func getString(t any) (string, bool) {
	z, ok := t.(string)
	if ok {
		return z, true
	}

	x, ok := t.(interface{ String() string })
	if ok {
		return x.String(), true
	}

	return "", false
}

func (c *counter) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	con, err := c.dialer.PacketConn(addr)
	if err != nil {
		return nil, fmt.Errorf("dial packet conn failed: %w", err)
	}
	z := &packetConn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   getAddr(addr),
			Local:  con.LocalAddr().String(),
			Remote: addr.String(),
			Type: &statistic.ConnectionNetType{
				ConnType:       "udp",
				UnderlyingType: con.LocalAddr().Network(),
			},
			Extra: extraMap(addr),
		},
		PacketConn: con,
		manager:    c,
	}

	c.storeConnection(z)
	return z, nil
}

func (c *counter) Conn(addr proxy.Address) (net.Conn, error) {
	con, err := c.dialer.Conn(addr)
	if err != nil {
		return nil, fmt.Errorf("dial conn failed: %w", err)
	}

	z := &conn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   getAddr(addr),
			Local:  con.LocalAddr().String(),
			Remote: con.RemoteAddr().String(),
			Type: &statistic.ConnectionNetType{
				ConnType:       "tcp",
				UnderlyingType: con.LocalAddr().Network(),
			},
			Extra: extraMap(addr),
		},
		Conn:    con,
		manager: c,
	}

	c.storeConnection(z)
	return z, nil
}
