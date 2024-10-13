package statistics

import (
	"context"
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Connections struct {
	gs.UnimplementedConnectionsServer

	netapi.Proxy

	Cache *TotalCache

	notify *notify

	connStore syncmap.SyncMap[uint64, connection]

	idSeed id.IDGenerator

	his FailedHistory
}

func NewConnStore(cache cache.Cache, dialer netapi.Proxy) *Connections {
	if dialer == nil {
		dialer = direct.Default
	}

	return &Connections{
		Proxy:  dialer,
		Cache:  NewTotalCache(cache),
		notify: newNotify(),
	}
}

func (c *Connections) Notify(_ *emptypb.Empty, s gs.Connections_NotifyServer) error {
	id, done := c.notify.register(s, c.connStore.RangeValues)
	defer c.notify.unregister(id)
	log.Debug("new notify client", "id", id)
	defer log.Debug("remove notify client", "id", id)

	select {
	case <-s.Context().Done():
		return s.Context().Err()
	case <-done.Done():
		return done.Err()
	}
}

func (c *Connections) Conns(context.Context, *emptypb.Empty) (*gs.NotifyNewConnections, error) {
	return &gs.NotifyNewConnections{
		Connections: slice.CollectTo(c.connStore.RangeValues, connToStatistic),
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

	for _, v := range c.connStore.Range {
		v.Close()
	}

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
		metrics.Counter.RemoveConnection(1)
		log.Debug("close conn", "id", z.Info().GetId())
	}

	c.notify.pubRemoveConn(id)
}

func (c *Connections) storeConnection(o connection) {
	c.connStore.Store(o.Info().GetId(), o)
	c.notify.pubNewConn(o)
	log.Select(slog.LevelDebug).PrintFunc("new conn", slogArgs(o))
}

func (c *Connections) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	con, err := c.Proxy.PacketConn(ctx, addr)
	if err != nil {
		c.his.Push(ctx, err, "udp", addr)
		return nil, err
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

func getRealAddr(store *netapi.Context, addr netapi.Address) string {
	if store.DomainString != "" {
		return store.DomainString
	}

	return addr.String()
}

func (c *Connections) getConnection(ctx context.Context, conn interface{ LocalAddr() net.Addr }, addr netapi.Address) *statistic.Connection {
	store := netapi.GetContext(ctx)

	realAddr := getRealAddr(store, addr)

	metrics.Counter.AddConnection(realAddr)

	// https://github.com/google/gvisor/blob/a9bdef23522b5a2ff2a7ec07c3e0573885b46ecb/pkg/tcpip/adapters/gonet/gonet.go#L457
	connection := &statistic.Connection{
		Id:   c.idSeed.Generate(),
		Addr: realAddr,
		Type: &statistic.NetType{
			ConnType:       statistic.Type(statistic.Type_value[addr.Network()]),
			UnderlyingType: statistic.Type(statistic.Type_value[conn.LocalAddr().Network()]),
		},
		Extra: store.Map(),
	}

	if out := getRemote(conn); out != "" {
		connection.Extra["Outbound"] = out
	}
	return connection
}

func (c *Connections) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	con, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		c.his.Push(ctx, err, "tcp", addr)
		return nil, err
	}

	z := &conn{con, c.getConnection(ctx, con, addr), c}
	c.storeConnection(z)
	return z, nil
}

func (c *Connections) FailedHistory(context.Context, *emptypb.Empty) (*gs.FailedHistoryList, error) {
	return c.his.Get(), nil
}
