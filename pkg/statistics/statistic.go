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

	Cache     *TotalCache
	telemetry *telemetryRecorder
	userUsage *UserUsage

	notify      *notify
	persistence *connectionPersistence

	faildHistory FailedHistoryStore
	history      HistoryStore

	counters *counters

	connStore syncmap.SyncMap[uint64, connection]
	// Live-only sidecar: template pointers only; never pins leaf history arrays.
	traceStore syncmap.SyncMap[uint64, []*contractconnection.MatchTraceTemplate]

	idSeed            id.IDGenerator
	openedConnections atomic.Uint64
	failedConnections atomic.Uint64
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

func NewSQLiteConnStore(path string, dialer netapi.Proxy) *Connections {
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

	normalizePersistedFakeIPDestinations(db)
	clearPreviousSessions(db)

	infoStore := newSQLiteInfoStore(db)
	history := newSQLiteHistory(db)
	connections := &Connections{
		Proxy:        dialer,
		sqliteDB:     db,
		sqlite:       store,
		Cache:        newSQLiteTotalCache(db, nil),
		telemetry:    newTelemetryRecorder(db),
		notify:       newNotify(),
		faildHistory: newSQLiteFailedHistory(db),
		counters:     newCounters(),
		infoStore:    infoStore,
		history:      history,
	}
	connections.persistence = newConnectionPersistence(db, infoStore, history)
	return connections
}

func (c *Connections) allInfos() []contractconnection.Connection {
	if store, ok := c.infoStore.(*sqliteInfoStore); ok {
		ids := slice.CollectTo(c.connStore.RangeValues, func(x connection) uint64 { return x.ID() })
		if c.persistence != nil {
			return c.persistence.loadMany(ids, store.loadMany)
		}
		return store.loadMany(ids)
	}
	return slice.CollectTo(c.connStore.RangeValues, func(x connection) contractconnection.Connection {
		info, ok := c.infoStore.Load(x.ID())
		if !ok {
			return contractconnection.Connection{ID: formatUint64(x.ID())}
		}
		return info
	})
}

func (c *Connections) Notify(s control.ServerStream[contractconnection.Event]) error {
	// Subscribe before taking the snapshot so connection events during the
	// query are queued, including when this is the first subscriber.
	id, done := c.notify.register(s)
	defer c.notify.unregister(id)
	log.Debug("new notify client", "id", id)
	defer log.Debug("remove notify client", "id", id)

	entry, ok := c.notify.notifier.Load(id)
	if !ok {
		return done.Err()
	}
	if err := entry.Send(contractconnection.Event{
		Type:    "connections_added",
		Payload: contractconnection.Connections{Connections: c.allInfos()},
	}); err != nil {
		return err
	}
	for {
		select {
		case <-s.Context().Done():
			return s.Context().Err()
		case <-done.Done():
			return done.Err()
		case event := <-entry.events:
			if err := entry.Send(event); err != nil {
				return err
			}
		}
	}
}

func (c *Connections) Conns(context.Context) (contractconnection.Connections, error) {
	return contractconnection.Connections{Connections: c.allInfos()}, nil
}

// MatchTraceForConnection materializes a trace only for a selected active
// connection. Periodic listing, events, SQLite persistence and the hot routing
// path never expand the shared matcher template.
func (c *Connections) MatchTraceForConnection(id uint64, index int) (contractconnection.MatchTraceResponse, bool) {
	templates, ok := c.traceStore.Load(id)
	if !ok || index < 0 || index >= len(templates) {
		return contractconnection.MatchTraceResponse{}, false
	}
	var info contractconnection.Connection
	if c.persistence != nil {
		info, ok = c.persistence.loadOne(id)
	} else {
		info, ok = c.infoStore.Load(id)
	}
	if !ok || index >= len(info.MatchHistory) {
		return contractconnection.MatchTraceResponse{}, false
	}
	entry := info.MatchHistory[index]
	entry.TraceTemplate = nil
	entry.Trace = contractconnection.ReconstructMatchTrace(templates[index], entry.History)
	// The caller already holds the flat history. Do not send all leaves twice:
	// once in the reconstructed tree and again in the legacy history field.
	entry.History = nil
	return contractconnection.MatchTraceResponse{RuleIndex: index, Entry: entry}, true
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
	// Connection removal still needs the prepared metadata statements.
	// Release sessions and final traffic counters before closing the stores.
	for _, v := range c.connStore.Range {
		if er := v.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if er := c.persistence.Close(); er != nil {
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
	c.telemetry.Close()
	if er := c.userUsage.Close(); er != nil {
		err = errors.Join(err, er)
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
	c.traceStore.Delete(id)
	if _, ok := c.connStore.LoadAndDelete(id); ok {
		metrics.Counter.RemoveConnection(1)
	}

	if c.persistence != nil {
		c.persistence.Delete(id)
	} else {
		c.infoStore.Delete(id)
	}
	if counter := c.counters.Remove(id); counter != nil {
		c.telemetry.Remove(counter.telemetry)
		counter.usage.end()
	}
	c.notify.pubRemoveConn(id)
}

func (c *Connections) storeConnection(o connection, info contractconnection.Connection) {
	metrics.Counter.AddConnection(info.Addr)

	id, _ := strconv.ParseUint(info.ID, 10, 64)
	c.connStore.Store(id, o)
	if len(info.MatchHistory) > 0 {
		templates := make([]*contractconnection.MatchTraceTemplate, len(info.MatchHistory))
		for i, entry := range info.MatchHistory {
			templates[i] = entry.TraceTemplate
		}
		c.traceStore.Store(id, templates)
	}
	c.openedConnections.Add(1)
	if c.persistence != nil {
		c.persistence.Store(id, info)
	} else {
		c.infoStore.Store(id, info)
		c.history.Push(info)
	}
	c.notify.pubNewConn(info)
}

func (c *Connections) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	con, err := c.Proxy.PacketConn(ctx, addr)
	if err != nil {
		c.faildHistory.Push(ctx, err, "udp", addr)
		c.recordFailure(ctx, "udp", addr, err)
		return nil, err
	}

	id := c.idSeed.Generate()
	info := c.getConnection(ctx, con, addr, id)
	counter := newCounter(c.Cache, c.telemetry.Register(c.telemetryConnection(ctx, info)))
	counter.usage = c.userUsage.register(info, counter, trafficIdentityContext(ctx))

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
		c.recordFailure(ctx, "ip", addr, err)
		return 0, err
	}

	conn := c.getConnection(ctx, nil, addr, c.idSeed.Generate())
	conn.Network.ConnType = "ip"
	conn.Network.UnderlyingType = "ip"

	c.history.Push(conn)
	return resp, nil
}

func (c *Connections) recordFailure(ctx context.Context, protocol string, addr netapi.Address, err error) {
	c.failedConnections.Add(1)
	info := c.getConnection(ctx, nil, addr, 0)
	info.Network.ConnType = protocol
	c.telemetry.RecordFailure(c.telemetryConnection(ctx, info))
	c.userUsage.failure(info, err)
}

func (c *Connections) telemetryConnection(ctx context.Context, info contractconnection.Connection) contractconnection.Connection {
	nc := netapi.GetContext(ctx)
	info.Process = nc.GetProcessName()
	info.MatchHistory = nc.MatchHistory()
	return info
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

	outbound, outboundGeo := getRemote(conn, nc.ConnOptions().Maxminddb())

	selectorID, selectorName := nc.Selector()
	ruleID, ruleName := nc.MatchedRule()
	var userID, credentialID string
	var groupIDs []string
	if identity := netapi.TrafficIdentity(nc); identity != nil {
		userID, credentialID = identity.UserID, identity.CredentialID
		groupIDs = identity.GroupIDs
	}
	connection := contractconnection.Connection{AccessDecision: netapi.TrafficAccessDecision(nc), UserID: userID, CredentialID: credentialID, GroupIDs: groupIDs,
		ID:          formatUint64(id),
		Addr:        getRealAddr(nc, addr),
		Network:     contractconnection.NetworkType{ConnType: addr.Network()},
		Source:      stringerValue(nc.Source),
		Inbound:     stringerValue(nc.GetInbound()),
		InboundName: nc.GetInboundName(),
		InboundID:   nc.GetInboundID(),
		Interface:   nc.GetInterface(),
		Outbound:    outbound,
		LocalAddr:   getLocal(conn),
		Destination: stringerValue(nc.Destination),
		FakeIP:      stringerValue(nc.GetFakeIP()),
		Hosts:       stringerValue(nc.GetHosts()),

		Domain:     nc.GetDomainString(),
		IP:         nc.GetIPString(),
		SelectorID: selectorID, SelectorName: selectorName,
		RuleID: ruleID, RuleName: ruleName,
		NodeID:       nc.Hash,
		NodeName:     nc.NodeName,
		Protocol:     nc.GetProtocol(),
		Process:      nc.GetProcessName(),
		PID:          formatUint64ZeroEmpty(uint64(nc.GetProcessPid())),
		UID:          formatUint64ZeroEmpty(uint64(nc.GetProcessUid())),
		Mode:         nc.ConnOptions().RouteMode(),
		UDPMigrateID: formatUint64ZeroEmpty(nc.GetUDPMigrateID()),

		Geo:           nc.GetGeo(),
		OutboundGeo:   outboundGeo,
		TLSServerName: nc.GetTLSServerName(),
		HTTPHost:      nc.GetHTTPHost(),
		Component:     nc.GetComponent(),
		MatchHistory:  nc.MatchHistory(),
		Resolver:      resolverName(nc.ConnOptions().Resolver().Resolver()),
		ListNames:     nc.ConnOptions().MatchedListNames(),
		Lists:         nc.ConnOptions().Lists()}

	if conn != nil {
		if local := conn.LocalAddr(); local != nil {
			connection.Network.UnderlyingType = local.Network()
		}
	}

	return connection
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
	return c.ConnWithProxy(ctx, addr, c.Proxy)
}

// ConnWithProxy records a preselected Gateway dial in the ordinary Connections
// and traffic stores, without selecting an outbound again at connection time.
func (c *Connections) ConnWithProxy(ctx context.Context, addr netapi.Address, proxy netapi.Proxy) (net.Conn, error) {
	con, err := proxy.Conn(ctx, addr)
	if err != nil {
		c.faildHistory.Push(ctx, err, "tcp", addr)
		c.recordFailure(ctx, "tcp", addr, err)
		return nil, err
	}

	id := c.idSeed.Generate()
	info := c.getConnection(ctx, con, addr, id)
	counter := newCounter(c.Cache, c.telemetry.Register(c.telemetryConnection(ctx, info)))
	counter.usage = c.userUsage.register(info, counter, trafficIdentityContext(ctx))

	z := &conn{
		Conn:    con,
		id:      id,
		onClose: func() { c.Remove(id) },
		counter: counter,
	}

	c.counters.Store(z.id, counter)
	c.storeConnection(z, info)
	return z.withBufferReader(), nil
}

func (c *Connections) FailedHistory(context.Context) (contractconnection.FailedHistoryList, error) {
	return c.faildHistory.Get(), nil
}

func (c *Connections) AllHistory(context.Context) (contractconnection.AllHistoryList, error) {
	if c.persistence != nil {
		if err := c.persistence.flush(); err != nil {
			log.Warn("flush connection persistence before history query failed", "err", err)
		}
	}
	return c.history.Get(), nil
}

type counters struct {
	store map[uint64]*Counter
	mu    sync.RWMutex
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

func (c *counters) Remove(id uint64) *Counter {
	c.mu.Lock()
	counter := c.store[id]
	delete(c.store, id)
	c.mu.Unlock()
	return counter
}

func (c *counters) Load() map[string]contractconnection.Counter {
	c.mu.RLock()
	defer c.mu.RUnlock()

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
	cache     *TotalCache
	telemetry *dimensionCounter
	usage     *usageSession
	download  atomic.Uint64
	upload    atomic.Uint64
}

func newCounter(cache *TotalCache, telemetry *dimensionCounter) *Counter {
	return &Counter{cache: cache, telemetry: telemetry}
}
func (c *Counter) AddDownload(n uint64) {
	c.cache.AddDownload(n)
	c.download.Add(n)
	if c.telemetry != nil {
		c.telemetry.download.Add(n)
		c.telemetry.markDirty()
	}
}

func (c *Counter) AddUpload(n uint64) {
	c.cache.AddUpload(n)
	c.upload.Add(n)
	if c.telemetry != nil {
		c.telemetry.upload.Add(n)
		c.telemetry.markDirty()
	}
}
func (c *Counter) LoadDownload() uint64 { return c.download.Load() }
func (c *Counter) LoadUpload() uint64   { return c.upload.Load() }
