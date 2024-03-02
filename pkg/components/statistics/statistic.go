package statistics

import (
	"context"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/convert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Connections struct {
	gs.UnimplementedConnectionsServer

	netapi.Proxy
	idSeed id.IDGenerator

	connStore syncmap.SyncMap[uint64, connection]

	processDumper listener.ProcessDumper
	Cache         *Cache

	notify *notify
}

func NewConnStore(cache *cache.Cache, dialer netapi.Proxy, processDumper listener.ProcessDumper) *Connections {
	if dialer == nil {
		dialer = direct.Default
	}

	return &Connections{
		Proxy:         dialer,
		processDumper: processDumper,
		Cache:         NewCache(cache),
		notify:        newNotify(),
	}
}

func (c *Connections) Notify(_ *emptypb.Empty, s gs.Connections_NotifyServer) error {
	id := c.notify.register(s, c.connStore.ValueSlice()...)
	defer c.notify.unregister(id)
	log.Debug("new notify client", "id", id)
	<-s.Context().Done()
	log.Debug("remove notify client", "id", id)
	return s.Context().Err()
}

func (c *Connections) Conns(context.Context, *emptypb.Empty) (*gs.NotifyNewConnections, error) {
	return &gs.NotifyNewConnections{
		Connections: slice.To(c.connStore.ValueSlice(),
			func(c connection) *statistic.Connection { return c.Info() }),
	}, nil
}

func (c *Connections) CloseConn(_ context.Context, x *gs.NotifyRemoveConnections) (*emptypb.Empty, error) {
	for _, x := range x.Ids {
		if z, ok := c.connStore.Load(x); ok {
			z.Close()
		}
	}
	return &emptypb.Empty{}, nil
}

func (c *Connections) Close() error {
	c.notify.Close()
	c.connStore.Range(func(key uint64, v connection) bool {
		v.Close()
		return true
	})

	c.Cache.Close()
	return nil
}

func (c *Connections) Total(context.Context, *emptypb.Empty) (*gs.TotalFlow, error) {
	return &gs.TotalFlow{
		Download: c.Cache.LoadDownload(),
		Upload:   c.Cache.LoadUpload(),
	}, nil
}

func (c *Connections) Remove(id uint64) {
	if z, ok := c.connStore.LoadAndDelete(id); ok {
		log.Debug("close conn", "id", z.ID())
	}

	c.notify.pubRemoveConns(id)
}

func (c *Connections) storeConnection(o connection) {
	c.connStore.Store(o.ID(), o)
	c.notify.pubNewConns(o)
	log.Debug("new conn",
		"id", o.ID(),
		"addr", o.Info().Addr,
		"src", o.Info().Extra[(netapi.SourceKey{}).String()],
		"network", o.Info().Type.ConnType,
		"outbound", o.Info().Extra["Outbound"],
	)
}

func (c *Connections) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	process := c.DumpProcess(ctx, addr)
	con, err := c.Proxy.PacketConn(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial packet conn (%s) failed: %w", process, err)
	}

	z := &packetConn{con, c.getConnection(ctx, con, addr), c}

	c.storeConnection(z)
	return z, nil
}

func getRemote(con any) string {
	r, ok := con.(interface{ RemoteAddr() net.Addr })
	if ok {
		// https://github.com/google/gvisor/blob/a9bdef23522b5a2ff2a7ec07c3e0573885b46ecb/pkg/tcpip/adapters/gonet/gonet.go#L457
		// gvisor TCPConn will return nil remoteAddr
		if addr := r.RemoteAddr(); addr != nil {
			return addr.String()
		}
	}

	return ""
}

func getRealAddr(store netapi.Store, addr netapi.Address) string {
	z, ok := store.Get(shunt.DOMAIN_MARK_KEY{})
	if ok {
		if s, ok := convert.ToString(z); ok {
			return s
		}
	}

	return addr.String()
}

func (c *Connections) getConnection(ctx context.Context, conn interface{ LocalAddr() net.Addr }, addr netapi.Address) *statistic.Connection {
	store := netapi.StoreFromContext(ctx)

	connection := &statistic.Connection{
		Id:   c.idSeed.Generate(),
		Addr: getRealAddr(store, addr),
		Type: &statistic.NetType{
			ConnType:       addr.NetworkType(),
			UnderlyingType: statistic.Type(statistic.Type_value[conn.LocalAddr().Network()]),
		},
		Extra: convert.ToStringMap(store),
	}

	if out := getRemote(conn); out != "" {
		connection.Extra["Outbound"] = out
	}
	return connection
}

func (c *Connections) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	process := c.DumpProcess(ctx, addr)
	con, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("dial conn (%s) failed: %w", process, err)
	}

	z := &conn{con, c.getConnection(ctx, con, addr), c}
	c.storeConnection(z)
	return z, nil
}

func (c *Connections) DumpProcess(ctx context.Context, addr netapi.Address) (s string) {
	if c.processDumper == nil {
		return
	}

	store := netapi.StoreFromContext(ctx)

	source, ok := store.Get(netapi.SourceKey{})
	if !ok {
		return
	}

	var dst any
	dst, ok = store.Get(netapi.InboundKey{})
	if !ok {
		dst, ok = store.Get(netapi.DestinationKey{})
	}
	if !ok {
		return
	}

	sourceAddr, err := convert.ToProxyAddress(addr.NetworkType(), source)
	if err != nil {
		return
	}

	dstAddr, err := convert.ToProxyAddress(addr.NetworkType(), dst)
	if err != nil {
		return
	}

	process, err := c.processDumper.ProcessName(addr.Network(), sourceAddr, dstAddr)
	if err != nil {
		return
	}

	store.Add("Process", process)
	return process
}
