package statistics

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/internal/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	grpcsts "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

type Connections struct {
	grpcsts.UnimplementedConnectionsServer

	dialer proxy.Proxy
	idSeed id.IDGenerator

	Download, Upload atomic.Uint64
	connStore        syncmap.SyncMap[uint64, connection]
}

func NewConnStore(dialer proxy.Proxy) *Connections {
	if dialer == nil {
		dialer = direct.Default
	}
	return &Connections{dialer: dialer}
}

func (c *Connections) Conns(context.Context, *emptypb.Empty) (*grpcsts.ConnectionsInfo, error) {
	resp := &grpcsts.ConnectionsInfo{}
	c.connStore.Range(func(key uint64, v connection) bool {
		resp.Connections = append(resp.Connections, v.Info())
		return true
	})

	return resp, nil
}

func (c *Connections) CloseConn(_ context.Context, x *grpcsts.ConnectionsId) (*emptypb.Empty, error) {
	for _, x := range x.Ids {
		if z, ok := c.connStore.Load(x); ok {
			z.Close()
		}
	}
	return &emptypb.Empty{}, nil
}

func (c *Connections) Close() error {
	c.connStore.Range(func(key uint64, v connection) bool {
		v.Close()
		return true
	})

	return nil
}

func (c *Connections) Total(context.Context, *emptypb.Empty) (*grpcsts.TotalFlow, error) {
	return &grpcsts.TotalFlow{Download: c.Download.Load(), Upload: c.Upload.Load()}, nil
}

func (c *Connections) Remove(id uint64) {
	if z, ok := c.connStore.LoadAndDelete(id); ok {
		log.Debugln("close", c.cString(z))
	}
}

func (c *Connections) storeConnection(o connection) {
	log.Debugf(c.cString(o))
	c.connStore.Store(o.Info().GetId(), o)
}

func (c *Connections) cString(oo connection) (s string) {
	if !log.IsOutput(protolog.LogLevel_debug) {
		return
	}

	str := pool.GetBuffer()
	defer pool.PutBuffer(str)

	o := oo.Info()

	for k, v := range o.GetExtra() {
		str.WriteString(fmt.Sprintf("%s: %s,", k, v))
	}
	return fmt.Sprintf("%v| <%s>: %v(%s), %s <-> %s",
		o.GetId(), o.GetType(), o.GetAddr(), str.String(), o.GetLocal(), o.GetRemote())
}

func (c *Connections) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	con, err := c.dialer.PacketConn(addr)
	if err != nil {
		return nil, fmt.Errorf("dial packet conn failed: %w", err)
	}

	z := &packetConn{con, c.generateConnection("udp", addr, con), c}

	c.storeConnection(z)
	return z, nil
}

func (c *Connections) Conn(addr proxy.Address) (net.Conn, error) {
	con, err := c.dialer.Conn(addr)
	if err != nil {
		return nil, fmt.Errorf("dial conn failed: %w", err)
	}

	z := &conn{con, c.generateConnection("tcp", addr, con), c}

	c.storeConnection(z)
	return z, nil
}

func (c *Connections) generateConnection(network string, addr proxy.Address, con interface{ LocalAddr() net.Addr }) *statistic.Connection {
	var remote string
	r, ok := con.(interface{ RemoteAddr() net.Addr })
	if ok {
		remote = r.RemoteAddr().String()
	} else {
		remote = addr.String()
	}

	return &statistic.Connection{
		Id:     c.idSeed.Generate(),
		Addr:   getAddr(addr),
		Local:  con.LocalAddr().String(),
		Remote: remote,
		Type: &statistic.NetType{
			ConnType:       network,
			UnderlyingType: con.LocalAddr().Network(),
		},
		Extra: extraMap(addr),
	}
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
