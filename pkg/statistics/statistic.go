package statistics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/maxminddb"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Connections struct {
	api.UnimplementedConnectionsServer

	netapi.Proxy

	Cache *TotalCache

	notify *notify

	faildHistory *FailedHistory
	history      *History

	connStore syncmap.SyncMap[uint64, connection]
	infoStore InfoCache
	counters  *counters

	idSeed id.IDGenerator
}

func NewConnStore(cache cache.Cache, dialer netapi.Proxy) *Connections {
	if dialer == nil {
		dialer = direct.Default
	}

	return &Connections{
		Proxy:        dialer,
		Cache:        NewTotalCache(cache.NewCache("flow_data")),
		notify:       newNotify(),
		faildHistory: NewFailedHistory(),
		counters:     newCounters(),
		infoStore:    newInfoStore(cache.NewCache("connection_data")),
		history:      NewHistory(newInfoStore(cache.NewCache("history_data"))),
	}
}

func (c *Connections) allInfos() []*statistic.Connection {
	return slice.CollectTo(c.connStore.RangeValues, func(x connection) *statistic.Connection {
		info, ok := c.infoStore.Load(x.ID())
		if !ok {
			return statistic.Connection_builder{
				Id: proto.Uint64(x.ID()),
			}.Build()
		}
		return info
	})
}

func (c *Connections) Notify(_ *emptypb.Empty, s api.Connections_NotifyServer) error {
	id, done := c.notify.register(s, c.allInfos())
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

func (c *Connections) Conns(context.Context, *emptypb.Empty) (*api.NotifyNewConnections, error) {
	return (&api.NotifyNewConnections_builder{Connections: c.allInfos()}).Build(), nil
}

func (c *Connections) CloseConn(_ context.Context, x *api.NotifyRemoveConnections) (*emptypb.Empty, error) {
	for _, x := range x.GetIds() {
		if z, ok := c.connStore.Load(x); ok {
			_ = z.Close()
		}
	}
	// trigger to refresh web
	c.notify.trigger()
	return &emptypb.Empty{}, nil
}

func (c *Connections) Close() error {
	var err error

	if er := c.notify.Close(); er != nil {
		err = errors.Join(err, er)
	}

	if er := c.history.Close(); er != nil {
		err = errors.Join(err, er)
	}

	if er := c.infoStore.Close(); er != nil {
		err = errors.Join(err, er)
	}

	for _, v := range c.connStore.Range {
		if er := v.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	c.Cache.Close()

	return err
}

func (c *Connections) Total(context.Context, *emptypb.Empty) (*api.TotalFlow, error) {
	return api.TotalFlow_builder{
		Download: proto.Uint64(c.Cache.LoadDownload()),
		Upload:   proto.Uint64(c.Cache.LoadUpload()),
		Counters: c.counters.Load(),
	}.Build(), nil
}

func (c *Connections) Remove(id uint64) {
	if _, ok := c.connStore.LoadAndDelete(id); ok {
		metrics.Counter.RemoveConnection(1)
	}

	c.infoStore.Delete(id)
	c.counters.Remove(id)
	c.notify.pubRemoveConn(id)
}

func (c *Connections) storeConnection(o connection, info *statistic.Connection) {
	metrics.Counter.AddConnection(info.GetAddr())

	id := info.GetId()
	c.connStore.Store(id, o)
	c.infoStore.Store(id, info)
	c.notify.pubNewConn(info)
	c.history.Push(info)
}

func (c *Connections) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	con, err := c.Proxy.PacketConn(ctx, addr)
	if err != nil {
		c.faildHistory.Push(ctx, err, statistic.Type_udp, addr)
		return nil, err
	}

	counter := newCounter(c.Cache)

	info := c.getConnection(ctx, con, addr)
	id := info.GetId()

	z := &packetConn{
		PacketConn: con,
		id:         id,
		onClose:    func() { c.Remove(id) },
		counter:    counter,
	}

	c.counters.Store(z.id, counter)

	c.storeConnection(z, info)
	return z, nil
}

func (c *Connections) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	resp, err := c.Proxy.Ping(ctx, addr)
	if err != nil {
		c.faildHistory.Push(ctx, err, statistic.Type_ip, addr)
		return 0, err
	}

	conn := c.getConnection(ctx, nil, addr)
	conn.GetType().SetConnType(statistic.Type_ip)
	conn.GetType().SetUnderlyingType(statistic.Type_ip)

	c.history.Push(conn)
	return resp, nil
}

func getRemote(con any, gg *maxminddb.MaxMindDB) (addrStr string, geo string) {
	if con == nil {
		return
	}

	r, ok := con.(interface{ RemoteAddr() net.Addr })
	if !ok {
		return
	}

	// https://github.com/google/gvisor/blob/a9bdef23522b5a2ff2a7ec07c3e0573885b46ecb/pkg/tcpip/adapters/gonet/gonet.go#L457
	// gvisor TCPConn will return nil remoteAddr
	addr := r.RemoteAddr()
	if addr == nil {
		return
	}

	addrStr = addr.String()

	if gg == nil {
		return
	}

	ad, err := netapi.ParseSysAddr(addr)
	if err != nil || ad.IsFqdn() {
		return
	}

	cun, _ := gg.Lookup(ad.(netapi.IPAddress).AddrPort().Addr())
	geo = cun

	return
}

func getLocal(con interface{ LocalAddr() net.Addr }) string {
	if con == nil {
		return ""
	}

	// https://github.com/google/gvisor/blob/a9bdef23522b5a2ff2a7ec07c3e0573885b46ecb/pkg/tcpip/adapters/gonet/gonet.go#L457
	// gvisor TCPConn will return nil remoteAddr
	if addr := con.LocalAddr(); addr != nil {
		return addr.String()
	}

	return ""
}

func getRealAddr(store *netapi.Context, addr netapi.Address) string {
	if store.GetDomainString() != "" {
		return store.GetDomainString()
	}

	return addr.String()
}

func (c *Connections) getConnection(ctx context.Context, conn interface{ LocalAddr() net.Addr }, addr netapi.Address) *statistic.Connection {
	nc := netapi.GetContext(ctx)

	outbound, outboundGeo := getRemote(conn, nc.ConnOptions().Maxminddb())

	connection := &statistic.Connection_builder{
		Id:   proto.Uint64(c.idSeed.Generate()),
		Addr: proto.String(getRealAddr(nc, addr)),
		Type: (&statistic.NetType_builder{
			ConnType: statistic.Type(statistic.Type_value[addr.Network()]).Enum(),
		}).Build(),
		Geo:          stringOrNil(nc.GetGeo()),
		Source:       stringerOrNil(nc.Source),
		Inbound:      stringerOrNil(nc.GetInbound()),
		InboundName:  stringOrNil(nc.GetInboundName()),
		Interface:    stringOrNil(nc.GetInterface()),
		Outbound:     stringOrNil(outbound),
		OutboundGeo:  stringOrNil(outboundGeo),
		LocalAddr:    stringOrNil(getLocal(conn)),
		Destionation: stringerOrNil(nc.Destination),
		FakeIp:       stringerOrNil(nc.GetFakeIP()),
		Hosts:        stringerOrNil(nc.GetHosts()),

		Domain:   stringOrNil(nc.GetDomainString()),
		Ip:       stringOrNil(nc.GetIPString()),
		Tag:      stringOrNil(nc.GetTag()),
		Hash:     stringOrNil(nc.Hash),
		NodeName: stringOrNil(nc.NodeName),
		Protocol: stringOrNil(nc.GetProtocol()),
		Process:  stringOrNil(nc.GetProcessName()),

		TlsServerName: stringOrNil(nc.GetTLSServerName()),
		HttpHost:      stringOrNil(nc.GetHTTPHost()),
		Component:     stringOrNil(nc.GetComponent()),
		Mode:          nc.Mode.Enum(),
		MatchHistory:  nc.MatchHistory(),
		UdpMigrateId:  uint64OrNil(nc.GetUDPMigrateID()),
		Pid:           uint64OrNil(uint64(nc.GetProcessPid())),
		Uid:           uint64OrNil(uint64(nc.GetProcessUid())),
		Resolver:      resolverNameOrNil(nc.ConnOptions().Resolver().Resolver()),
	}

	if conn != nil {
		connection.Type.SetUnderlyingType(statistic.Type(statistic.Type_value[conn.LocalAddr().Network()]))
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

func resolverNameOrNil(resolver netapi.Resolver) *string {
	if resolver == nil {
		return nil
	}
	return proto.String(resolver.Name())
}

func (c *Connections) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	con, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		c.faildHistory.Push(ctx, err, statistic.Type_tcp, addr)
		return nil, err
	}

	counter := newCounter(c.Cache)

	info := c.getConnection(ctx, con, addr)

	id := info.GetId()

	z := &conn{
		Conn:    con,
		id:      id,
		onClose: func() { c.Remove(id) },
		counter: counter,
	}

	c.counters.Store(z.id, counter)
	c.storeConnection(z, info)
	return z, nil
}

func (c *Connections) FailedHistory(context.Context, *emptypb.Empty) (*api.FailedHistoryList, error) {
	return c.faildHistory.Get(), nil
}

func (c *Connections) AllHistory(context.Context, *emptypb.Empty) (*api.AllHistoryList, error) {
	return c.history.Get(), nil
}

type counters struct {
	mu    sync.Mutex
	store map[uint64]*Counter
}

func newCounters() *counters {
	return &counters{
		store: map[uint64]*Counter{},
	}
}

func (c *counters) Store(id uint64, counter *Counter) {
	c.mu.Lock()
	c.store[id] = counter
	c.mu.Unlock()
}

func (c *counters) Remove(id uint64) {
	c.mu.Lock()
	delete(c.store, id)
	c.mu.Unlock()
}

func (c *counters) Load() map[uint64]*api.Counter {
	c.mu.Lock()
	defer c.mu.Unlock()

	tmp := make(map[uint64]*api.Counter, len(c.store))

	for k, v := range c.store {
		tmp[k] = api.Counter_builder{
			Download: proto.Uint64(v.LoadDownload()),
			Upload:   proto.Uint64(v.LoadUpload()),
		}.Build()
	}

	return tmp
}

type Counter struct {
	cache    *TotalCache
	download atomic.Uint64
	upload   atomic.Uint64
}

func newCounter(cache *TotalCache) *Counter { return &Counter{cache: cache} }
func (c *Counter) AddDownload(n uint64) {
	c.cache.AddDownload(n)
	c.download.Add(n)
}
func (c *Counter) AddUpload(n uint64) {
	c.cache.AddUpload(n)
	c.upload.Add(n)
}
func (c *Counter) LoadDownload() uint64 { return c.download.Load() }
func (c *Counter) LoadUpload() uint64   { return c.upload.Load() }
