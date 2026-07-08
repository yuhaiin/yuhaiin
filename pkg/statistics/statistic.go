package statistics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/control"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	schemaapi "github.com/Asutorufa/yuhaiin/pkg/schema/api"
	"github.com/Asutorufa/yuhaiin/pkg/schema/statistic"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
	"github.com/Asutorufa/yuhaiin/pkg/utils/slice"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type Connections struct {
	netapi.Proxy

	infoStore InfoCache
	sqliteDB  *sql.DB
	sqlite    *storagesqlite.Store

	Cache *TotalCache

	notify *notify

	faildHistory FailedHistoryStore
	history      HistoryStore

	counters *counters

	connStore syncmap.SyncMap[uint64, connection]

	idSeed id.IDGenerator
}

type InfoCache interface {
	Load(id uint64) (*statistic.Connection, bool)
	Store(id uint64, info *statistic.Connection)
	Delete(id uint64)
	io.Closer
}

type FailedHistoryStore interface {
	Push(context.Context, error, statistic.Type, netapi.Address)
	Get() *schemaapi.FailedHistoryList
	Close() error
}

type HistoryStore interface {
	Push(*statistic.Connection)
	Get() *schemaapi.AllHistoryList
	Close() error
}

func NewSQLiteConnStore(path string, dialer netapi.Proxy, legacyFlow ...cache.Geter) *Connections {
	if dialer == nil {
		dialer = direct.Default
	}

	store, err := storagesqlite.Open(context.Background(), path)
	if err != nil {
		log.Warn("open sqlite connection store failed", "err", err)
	}

	var db *sql.DB
	if store != nil {
		db = store.DB()
	}

	markInterruptedSessions(db)

	return &Connections{
		Proxy:        dialer,
		sqliteDB:     db,
		sqlite:       store,
		Cache:        newSQLiteTotalCache(db, nil, legacyFlow...),
		notify:       newNotify(),
		faildHistory: newSQLiteFailedHistory(db),
		counters:     newCounters(),
		infoStore:    newSQLiteInfoStore(db),
		history:      newSQLiteHistory(db),
	}
}

func (c *Connections) allInfos() []*statistic.Connection {
	return slice.CollectTo(c.connStore.RangeValues, func(x connection) *statistic.Connection {
		info, ok := c.infoStore.Load(x.ID())
		if !ok {
			return statistic.Connection_builder{
				Id: new(x.ID()),
			}.Build()
		}
		return info
	})
}

func (c *Connections) Notify(_ *schemaapi.Empty, s control.ServerStream[schemaapi.NotifyData]) error {
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

func (c *Connections) Conns(context.Context, *schemaapi.Empty) (*schemaapi.NotifyNewConnections, error) {
	return &schemaapi.NotifyNewConnections{Connections: c.allInfos()}, nil
}

func (c *Connections) CloseConn(_ context.Context, x *schemaapi.NotifyRemoveConnections) (*schemaapi.Empty, error) {
	for _, x := range x.GetIds() {
		if z, ok := c.connStore.Load(x); ok {
			_ = z.Close()
		}
	}
	// trigger to refresh web
	c.notify.trigger()
	return &schemaapi.Empty{}, nil
}

func (c *Connections) Close() error {
	var err error

	if er := c.notify.Close(); er != nil {
		err = errors.Join(err, er)
	}

	if er := c.history.Close(); er != nil {
		err = errors.Join(err, er)
	}

	if er := c.faildHistory.Close(); er != nil {
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

	if c.sqlite != nil {
		if er := c.sqlite.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

func (c *Connections) Total(context.Context, *schemaapi.Empty) (*schemaapi.TotalFlow, error) {
	return &schemaapi.TotalFlow{
		Download: c.Cache.LoadDownload(),
		Upload:   c.Cache.LoadUpload(),
		Counters: c.counters.Load(),
	}, nil
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

func getRemote(con any, gg netapi.MaxMindDB) (addrStr string, geo string) {
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

	maxminddb := nc.ConnOptions().Maxminddb()
	if !configuration.ExtendedStatsEnabled.Load() {
		maxminddb = nil
	}

	outbound, outboundGeo := getRemote(conn, maxminddb)

	connection := &statistic.Connection_builder{
		Id:   new(c.idSeed.Generate()),
		Addr: new(getRealAddr(nc, addr)),
		Type: statistic.NetType_builder{
			ConnType: statistic.Type(statistic.Type_value[addr.Network()]).Enum(),
		}.Build(),
		Source:       stringerOrNil(nc.Source),
		Inbound:      stringerOrNil(nc.GetInbound()),
		InboundName:  stringOrNil(nc.GetInboundName()),
		Interface:    stringOrNil(nc.GetInterface()),
		Outbound:     stringOrNil(outbound),
		LocalAddr:    stringOrNil(getLocal(conn)),
		Destionation: stringerOrNil(nc.Destination),
		FakeIp:       stringerOrNil(nc.GetFakeIP()),
		Hosts:        stringerOrNil(nc.GetHosts()),

		Domain:       stringOrNil(nc.GetDomainString()),
		Ip:           stringOrNil(nc.GetIPString()),
		Tag:          stringOrNil(nc.GetTag()),
		Hash:         stringOrNil(nc.Hash),
		NodeName:     stringOrNil(nc.NodeName),
		Protocol:     stringOrNil(nc.GetProtocol()),
		Mode:         nc.ConnOptions().RouteMode().Enum(),
		UdpMigrateId: uint64OrNil(nc.GetUDPMigrateID()),
	}

	if configuration.ExtendedStatsEnabled.Load() {
		connection.Geo = stringOrNil(nc.GetGeo())
		connection.OutboundGeo = stringOrNil(outboundGeo)
		connection.Process = stringOrNil(nc.GetProcessName())
		connection.TlsServerName = stringOrNil(nc.GetTLSServerName())
		connection.HttpHost = stringOrNil(nc.GetHTTPHost())
		connection.Component = stringOrNil(nc.GetComponent())
		connection.MatchHistory = ToMatchHistoryEntry(nc.MatchHistory())
		connection.Pid = uint64OrNil(uint64(nc.GetProcessPid()))
		connection.Uid = uint64OrNil(uint64(nc.GetProcessUid()))
		connection.Resolver = resolverNameOrNil(nc.ConnOptions().Resolver().Resolver())
		connection.Lists = nc.ConnOptions().Lists()
	}

	if conn != nil {
		connection.Type.SetUnderlyingType(statistic.Type(statistic.Type_value[conn.LocalAddr().Network()]))
	}

	return connection.Build()
}

func ToMatchHistoryEntry(entry []*netapi.MatchHistoryEntry) []*statistic.MatchHistoryEntry {
	mhis := make([]*statistic.MatchHistoryEntry, 0, len(entry))
	for _, e := range entry {
		his := make([]*statistic.MatchResult, 0, len(e.UnmatchedHistory))
		for _, uh := range e.UnmatchedHistory {
			r := &statistic.MatchResult{}
			r.SetListName(uh.Value())
			his = append(his, r)
		}

		if m := e.MatchedHistory.Value(); m != "" {
			r := &statistic.MatchResult{}
			r.SetListName(m)
			r.SetMatched(true)
			his = append(his, r)
		}

		h := &statistic.MatchHistoryEntry{}
		h.SetRuleName(e.RuleName.Value())
		h.SetHistory(his)
		mhis = append(mhis, h)
	}

	return mhis
}

func uint64OrNil(i uint64) *uint64 {
	if i == 0 {
		return nil
	}
	return new(i)
}

func stringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return new(str)
}

func stringerOrNil(str fmt.Stringer) *string {
	if str == nil {
		return nil
	}
	return new(str.String())
}

func resolverNameOrNil(resolver netapi.Resolver) *string {
	if resolver == nil {
		return nil
	}
	return new(resolver.Name())
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

func (c *Connections) FailedHistory(context.Context, *schemaapi.Empty) (*schemaapi.FailedHistoryList, error) {
	return c.faildHistory.Get(), nil
}

func (c *Connections) AllHistory(context.Context, *schemaapi.Empty) (*schemaapi.AllHistoryList, error) {
	return c.history.Get(), nil
}

type counters struct {
	store map[uint64]*Counter
	mu    sync.Mutex
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

func (c *counters) Load() map[uint64]schemaapi.Counter {
	c.mu.Lock()
	defer c.mu.Unlock()

	tmp := make(map[uint64]schemaapi.Counter, len(c.store))

	for k, v := range c.store {
		tmp[k] = schemaapi.Counter{
			Download: v.LoadDownload(),
			Upload:   v.LoadUpload(),
		}
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
