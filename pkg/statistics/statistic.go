package statistics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/control"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
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
	Load(id uint64) (contractconnection.Connection, bool)
	Store(id uint64, info contractconnection.Connection)
	Delete(id uint64)
	io.Closer
}

type FailedHistoryStore interface {
	Push(context.Context, error, string, netapi.Address)
	Get() contractconnection.FailedHistoryList
	Close() error
}

type HistoryStore interface {
	Push(contractconnection.Connection)
	Get() contractconnection.AllHistoryList
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

func (c *Connections) allInfos() []contractconnection.Connection {
	return slice.CollectTo(c.connStore.RangeValues, func(x connection) contractconnection.Connection {
		info, ok := c.infoStore.Load(x.ID())
		if !ok {
			return contractconnection.Connection{ID: formatUint64(x.ID())}
		}
		return info
	})
}

func (c *Connections) Notify(s control.ServerStream[contractconnection.Event]) error {
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

func (c *Connections) Conns(context.Context) (contractconnection.Connections, error) {
	return contractconnection.Connections{Connections: c.allInfos()}, nil
}

func (c *Connections) CloseConn(_ context.Context, ids []uint64) error {
	for _, id := range ids {
		if z, ok := c.connStore.Load(id); ok {
			_ = z.Close()
		}
	}
	// trigger to refresh web
	c.notify.trigger()
	return nil
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

func (c *Connections) Total(context.Context) (contractconnection.TotalFlow, error) {
	return contractconnection.TotalFlow{
		Download: formatUint64(c.Cache.LoadDownload()),
		Upload:   formatUint64(c.Cache.LoadUpload()),
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

func (c *Connections) storeConnection(o connection, info contractconnection.Connection) {
	metrics.Counter.AddConnection(info.Addr)

	id, _ := strconv.ParseUint(info.ID, 10, 64)
	c.connStore.Store(id, o)
	c.infoStore.Store(id, info)
	c.notify.pubNewConn(info)
	c.history.Push(info)
}

func (c *Connections) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	con, err := c.Proxy.PacketConn(ctx, addr)
	if err != nil {
		c.faildHistory.Push(ctx, err, "udp", addr)
		return nil, err
	}

	counter := newCounter(c.Cache)

	id := c.idSeed.Generate()
	info := c.getConnection(ctx, con, addr, id)

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
		c.faildHistory.Push(ctx, err, "ip", addr)
		return 0, err
	}

	conn := c.getConnection(ctx, nil, addr, c.idSeed.Generate())
	conn.Network.ConnType = "ip"
	conn.Network.UnderlyingType = "ip"

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

func (c *Connections) getConnection(ctx context.Context, conn interface{ LocalAddr() net.Addr }, addr netapi.Address, id uint64) contractconnection.Connection {
	nc := netapi.GetContext(ctx)

	maxminddb := nc.ConnOptions().Maxminddb()
	if !configuration.ExtendedStatsEnabled.Load() {
		maxminddb = nil
	}

	outbound, outboundGeo := getRemote(conn, maxminddb)

	connection := contractconnection.Connection{
		ID:          formatUint64(id),
		Addr:        getRealAddr(nc, addr),
		Network:     contractconnection.NetworkType{ConnType: addr.Network()},
		Source:      stringerValue(nc.Source),
		Inbound:     stringerValue(nc.GetInbound()),
		InboundName: nc.GetInboundName(),
		Interface:   nc.GetInterface(),
		Outbound:    outbound,
		LocalAddr:   getLocal(conn),
		Destination: stringerValue(nc.Destination),
		FakeIP:      stringerValue(nc.GetFakeIP()),
		Hosts:       stringerValue(nc.GetHosts()),

		Domain:       nc.GetDomainString(),
		IP:           nc.GetIPString(),
		Tag:          nc.GetTag(),
		NodeID:       nc.Hash,
		NodeName:     nc.NodeName,
		Protocol:     nc.GetProtocol(),
		Mode:         nc.ConnOptions().RouteMode(),
		UDPMigrateID: formatUint64ZeroEmpty(nc.GetUDPMigrateID()),
	}

	if configuration.ExtendedStatsEnabled.Load() {
		connection.Geo = nc.GetGeo()
		connection.OutboundGeo = outboundGeo
		connection.Process = nc.GetProcessName()
		connection.TLSServerName = nc.GetTLSServerName()
		connection.HTTPHost = nc.GetHTTPHost()
		connection.Component = nc.GetComponent()
		connection.MatchHistory = ToMatchHistoryEntry(nc.MatchHistory())
		connection.PID = formatUint64ZeroEmpty(uint64(nc.GetProcessPid()))
		connection.UID = formatUint64ZeroEmpty(uint64(nc.GetProcessUid()))
		connection.Resolver = resolverName(nc.ConnOptions().Resolver().Resolver())
		connection.Lists = nc.ConnOptions().Lists()
	}

	if conn != nil {
		if local := conn.LocalAddr(); local != nil {
			connection.Network.UnderlyingType = local.Network()
		}
	}

	return connection
}

func ToMatchHistoryEntry(entry []*netapi.MatchHistoryEntry) []contractconnection.MatchHistoryEntry {
	mhis := make([]contractconnection.MatchHistoryEntry, 0, len(entry))
	for _, e := range entry {
		his := make([]contractconnection.MatchResult, 0, len(e.UnmatchedHistory))
		for _, uh := range e.UnmatchedHistory {
			his = append(his, contractconnection.MatchResult{ListName: uh.Value()})
		}

		if m := e.MatchedHistory.Value(); m != "" {
			his = append(his, contractconnection.MatchResult{ListName: m, Matched: true})
		}

		mhis = append(mhis, contractconnection.MatchHistoryEntry{
			RuleName: e.RuleName.Value(),
			History:  his,
		})
	}

	return mhis
}

func formatUint64(v uint64) string {
	return strconv.FormatUint(v, 10)
}

func formatUint64ZeroEmpty(i uint64) string {
	if i == 0 {
		return ""
	}
	return formatUint64(i)
}

func stringerValue(str fmt.Stringer) string {
	if str == nil {
		return ""
	}
	return str.String()
}

func resolverName(resolver netapi.Resolver) string {
	if resolver == nil {
		return ""
	}
	return resolver.Name()
}

func (c *Connections) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	con, err := c.Proxy.Conn(ctx, addr)
	if err != nil {
		c.faildHistory.Push(ctx, err, "tcp", addr)
		return nil, err
	}

	counter := newCounter(c.Cache)

	id := c.idSeed.Generate()
	info := c.getConnection(ctx, con, addr, id)

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

func (c *Connections) FailedHistory(context.Context) (contractconnection.FailedHistoryList, error) {
	return c.faildHistory.Get(), nil
}

func (c *Connections) AllHistory(context.Context) (contractconnection.AllHistoryList, error) {
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

func (c *counters) Load() map[string]contractconnection.Counter {
	c.mu.Lock()
	defer c.mu.Unlock()

	tmp := make(map[string]contractconnection.Counter, len(c.store))

	for k, v := range c.store {
		tmp[formatUint64(k)] = contractconnection.Counter{
			Download: formatUint64(v.LoadDownload()),
			Upload:   formatUint64(v.LoadUpload()),
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
