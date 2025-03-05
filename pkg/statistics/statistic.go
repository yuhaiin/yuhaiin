package statistics

import (
	"context"
	"fmt"
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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Connections struct {
	gs.UnimplementedConnectionsServer

	netapi.Proxy

	Cache *TotalCache

	notify *notify

	connStore syncmap.SyncMap[uint64, connection]

	idSeed id.IDGenerator

	faildHistory *FailedHistory
	history      *History
}

func NewConnStore(cache cache.Cache, dialer netapi.Proxy) *Connections {
	if dialer == nil {
		dialer = direct.Default
	}

	return &Connections{
		Proxy:        dialer,
		Cache:        NewTotalCache(cache),
		notify:       newNotify(),
		faildHistory: NewFailedHistory(),
		history:      NewHistory(),
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
	return (&gs.NotifyNewConnections_builder{
		Connections: slice.CollectTo(c.connStore.RangeValues, connToStatistic),
	}).Build(), nil
}

func (c *Connections) CloseConn(_ context.Context, x *gs.NotifyRemoveConnections) (*emptypb.Empty, error) {
	for _, x := range x.GetIds() {
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
	counters := map[uint64]*gs.Counter{}

	for _, v := range c.connStore.Range {
		counters[v.Info().GetId()] = gs.Counter_builder{
			Download: proto.Uint64(v.LoadDownload()),
			Upload:   proto.Uint64(v.LoadUpload()),
		}.Build()
	}

	return (&gs.TotalFlow_builder{
		Download: proto.Uint64(c.Cache.LoadDownload()),
		Upload:   proto.Uint64(c.Cache.LoadUpload()),
		Counters: counters,
	}).Build(), nil
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
	c.history.Push(o.Info())
	log.Select(slog.LevelDebug).PrintFunc("new conn", slogArgs(o))
}

func (c *Connections) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	con, err := c.Proxy.PacketConn(ctx, addr)
	if err != nil {
		c.faildHistory.Push(ctx, err, "udp", addr)
		return nil, err
	}

	z := &packetConn{
		PacketConn: con,
		info:       c.getConnection(ctx, con, addr),
		manager:    c,
	}

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

func getLocal(con interface{ LocalAddr() net.Addr }) string {
	// https://github.com/google/gvisor/blob/a9bdef23522b5a2ff2a7ec07c3e0573885b46ecb/pkg/tcpip/adapters/gonet/gonet.go#L457
	// gvisor TCPConn will return nil remoteAddr
	if addr := con.LocalAddr(); addr != nil {
		return addr.String()
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

	connection := &statistic.Connection_builder{
		Id:   proto.Uint64(c.idSeed.Generate()),
		Addr: proto.String(realAddr),
		Type: (&statistic.NetType_builder{
			ConnType:       statistic.Type(statistic.Type_value[addr.Network()]).Enum(),
			UnderlyingType: statistic.Type(statistic.Type_value[conn.LocalAddr().Network()]).Enum(),
		}).Build(),
		Source:       stringerOrNil(store.Source),
		Inbound:      stringerOrNil(store.Inbound),
		Outbound:     stringOrNil(getRemote(conn)),
		LocalAddr:    stringOrNil(getLocal(conn)),
		Destionation: stringerOrNil(store.Destination),
		FakeIp:       stringerOrNil(store.FakeIP),
		Hosts:        stringerOrNil(store.Hosts),

		Domain:   stringOrNil(store.DomainString),
		Ip:       stringOrNil(store.IPString),
		Tag:      stringOrNil(store.Tag),
		Hash:     stringOrNil(store.Hash),
		NodeName: stringOrNil(store.NodeName),
		Protocol: stringOrNil(store.Protocol),
		Process:  stringOrNil(store.Process),

		TlsServerName: stringOrNil(store.TLSServerName),
		HttpHost:      stringOrNil(store.HTTPHost),
		Component:     stringOrNil(store.Component),
		Mode:          store.Mode.Enum(),
		ModeReason:    stringOrNil(store.ModeReason),
		UdpMigrateId:  uint64OrNil(store.UDPMigrateID),
		Pid:           uint64OrNil(uint64(store.ProcessPid)),
		Uid:           uint64OrNil(uint64(store.ProcessUid)),
	}

	return connection.Build()
}

func uint64OrNil(i uint64) *uint64 {
	if i == 0 {
		return nil
	}
	return proto.Uint64(i)
}

func stringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return proto.String(str)
}

func stringerOrNil(str fmt.Stringer) *string {
	if str == nil {
		return nil
	}
	return proto.String(str.String())
}

func (c *Connections) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	con, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		c.faildHistory.Push(ctx, err, "tcp", addr)
		return nil, err
	}

	z := &conn{
		Conn:    con,
		info:    c.getConnection(ctx, con, addr),
		manager: c,
	}

	c.storeConnection(z)
	return z, nil
}

func (c *Connections) FailedHistory(context.Context, *emptypb.Empty) (*gs.FailedHistoryList, error) {
	return c.faildHistory.Get(), nil
}

func (c *Connections) AllHistory(context.Context, *emptypb.Empty) (*gs.AllHistoryList, error) {
	return c.history.Get(), nil
}
