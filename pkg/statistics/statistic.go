package statistics

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

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

	faildHistory *FailedHistory
	history      *History

	connStore syncmap.SyncMap[uint64, connection]
	infoStore InfoCache
	counters  *counters

	idSeed id.IDGenerator
}

func NewConnStore(cache, history, connection cache.Cache, dialer netapi.Proxy) *Connections {
	if dialer == nil {
		dialer = direct.Default
	}

	var infoStore InfoCache
	if connection != nil {
		infoStore = newInfoStore(connection)
	} else {
		infoStore = newInfoMemStore()
	}

	var historyStore InfoCache
	if history != nil {
		historyStore = newInfoStore(history)
	} else {
		historyStore = newInfoMemStore()
	}

	return &Connections{
		Proxy:        dialer,
		Cache:        NewTotalCache(cache),
		notify:       newNotify(),
		faildHistory: NewFailedHistory(),
		counters:     newCounters(),
		infoStore:    infoStore,
		history:      NewHistory(historyStore),
	}
}

func (c *Connections) allInfos() []*statistic.Connection {
	return slice.CollectTo(c.infoStore.RangeValues, func(x *statistic.Connection) *statistic.Connection {
		return x
	})
}

func (c *Connections) Notify(_ *emptypb.Empty, s gs.Connections_NotifyServer) error {
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

func (c *Connections) Conns(context.Context, *emptypb.Empty) (*gs.NotifyNewConnections, error) {
	return (&gs.NotifyNewConnections_builder{Connections: c.allInfos()}).Build(), nil
}

func (c *Connections) CloseConn(_ context.Context, x *gs.NotifyRemoveConnections) (*emptypb.Empty, error) {
	for _, x := range x.GetIds() {
		if z, ok := c.connStore.Load(x); ok {
			z.Close()
		}
	}
	// trigger to refresh web
	c.notify.trigger()
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
	return gs.TotalFlow_builder{
		Download: proto.Uint64(c.Cache.LoadDownload()),
		Upload:   proto.Uint64(c.Cache.LoadUpload()),
		Counters: c.counters.Load(),
	}.Build(), nil
}

func (c *Connections) Remove(id uint64) {
	if z, ok := c.connStore.LoadAndDelete(id); ok {
		metrics.Counter.RemoveConnection(1)
		log.Debug("close conn", "id", z.ID())
	}

	c.infoStore.Delete(id)
	c.counters.Remove(id)
	c.notify.pubRemoveConn(id)
}

func (c *Connections) storeConnection(o connection, info *statistic.Connection) {
	id := info.GetId()
	c.connStore.Store(id, o)
	c.infoStore.Store(id, info)
	c.notify.pubNewConn(info)
	c.history.Push(info)
	log.Select(slog.LevelDebug).PrintFunc("new conn", slogArgs(info))
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

func getRemote(con any) string {
	if con == nil {
		return ""
	}

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
	store := netapi.GetContext(ctx)

	realAddr := getRealAddr(store, addr)

	metrics.Counter.AddConnection(realAddr)

	connection := &statistic.Connection_builder{
		Id:   proto.Uint64(c.idSeed.Generate()),
		Addr: proto.String(realAddr),
		Type: (&statistic.NetType_builder{
			ConnType: statistic.Type(statistic.Type_value[addr.Network()]).Enum(),
		}).Build(),
		Source:       stringerOrNil(store.Source),
		Inbound:      stringerOrNil(store.GetInbound()),
		InboundName:  stringOrNil(store.GetInboundName()),
		Outbound:     stringOrNil(getRemote(conn)),
		LocalAddr:    stringOrNil(getLocal(conn)),
		Destionation: stringerOrNil(store.Destination),
		FakeIp:       stringerOrNil(store.GetFakeIP()),
		Hosts:        stringerOrNil(store.GetHosts()),

		Domain:   stringOrNil(store.GetDomainString()),
		Ip:       stringOrNil(store.GetIPString()),
		Tag:      stringOrNil(store.GetTag()),
		Hash:     stringOrNil(store.Hash),
		NodeName: stringOrNil(store.NodeName),
		Protocol: stringOrNil(store.GetProtocol()),
		Process:  stringOrNil(store.GetProcessName()),

		TlsServerName: stringOrNil(store.GetTLSServerName()),
		HttpHost:      stringOrNil(store.GetHTTPHost()),
		Component:     stringOrNil(store.GetComponent()),
		Mode:          store.Mode.Enum(),
		MatchHistory:  store.MatchHistory(),
		UdpMigrateId:  uint64OrNil(store.GetUDPMigrateID()),
		Pid:           uint64OrNil(uint64(store.GetProcessPid())),
		Uid:           uint64OrNil(uint64(store.GetProcessUid())),
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

func (c *Connections) FailedHistory(context.Context, *emptypb.Empty) (*gs.FailedHistoryList, error) {
	return c.faildHistory.Get(), nil
}

func (c *Connections) AllHistory(context.Context, *emptypb.Empty) (*gs.AllHistoryList, error) {
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

func (c *counters) Load() map[uint64]*gs.Counter {
	c.mu.Lock()
	defer c.mu.Unlock()

	tmp := make(map[uint64]*gs.Counter, len(c.store))

	for k, v := range c.store {
		tmp[k] = gs.Counter_builder{
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

type InfoCache interface {
	Load(id uint64) (*statistic.Connection, bool)
	Store(id uint64, info *statistic.Connection)
	RangeValues(f func(value *statistic.Connection) bool)
	Delete(id uint64)
	io.Closer
}

var _ InfoCache = (*infoStore)(nil)

type infoStore struct {
	ctx      context.Context
	cancel   context.CancelFunc
	memcache syncmap.SyncMap[uint64, *statistic.Connection]
	cache    cache.Cache
}

func newInfoStore(cache cache.Cache) *infoStore {
	ctx, cancel := context.WithCancel(context.TODO())
	c := &infoStore{
		cache:  cache,
		ctx:    ctx,
		cancel: cancel,
	}

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.Flush()
			}
		}
	}()

	return c
}

func (c *infoStore) Load(id uint64) (*statistic.Connection, bool) {
	cc, ok := c.memcache.Load(id)
	if ok {
		return cc, true
	}

	data, err := c.cache.Get(binary.BigEndian.AppendUint64([]byte{}, id))
	if err != nil {
		log.Warn("get info failed", "id", id, "err", err)
		return nil, false
	}
	var info statistic.Connection
	if err := proto.Unmarshal(data, &info); err != nil {
		log.Warn("unmarshal info failed", "id", id, "err", err)
		return nil, false
	}

	return &info, true
}

func (c *infoStore) Store(id uint64, info *statistic.Connection) {
	c.memcache.Store(id, info)
}

func (c *infoStore) Flush() {
	for id := range c.memcache.Range {
		info, ok := c.memcache.LoadAndDelete(id)
		if !ok {
			continue
		}

		data, err := proto.Marshal(info)
		if err != nil {
			log.Warn("marshal info failed", "id", id, "err", err)
			return
		}

		key := binary.BigEndian.AppendUint64([]byte{}, id)

		err = c.cache.Put(key, data)
		if err != nil {
			log.Warn("put info failed", "id", id, "err", err)
		}
	}
}

func (c *infoStore) Delete(id uint64) {
	_, ok := c.memcache.LoadAndDelete(id)
	if ok {
		return
	}

	err := c.cache.Delete(binary.BigEndian.AppendUint64([]byte{}, id))
	if err != nil {
		log.Warn("delete info failed", "id", id, "err", err)
	}
}

func (c *infoStore) Close() error {
	c.cancel()
	return c.cache.Close()
}

func (c *infoStore) Range(f func(key uint64, value *statistic.Connection) bool) error {
	return c.cache.Range(func(key []byte, value []byte) bool {
		var info statistic.Connection
		if err := proto.Unmarshal(value, &info); err != nil {
			return false
		}
		return f(binary.BigEndian.Uint64(key), &info)
	})
}

func (c *infoStore) RangeValues(f func(value *statistic.Connection) bool) {
	err := c.cache.Range(func(key, value []byte) bool {
		var info statistic.Connection
		if err := proto.Unmarshal(value, &info); err != nil {
			return false
		}
		return f(&info)
	})
	if err != nil {
		log.Warn("range info failed", "err", err)
	}
}

var _ InfoCache = (*infoMemStore)(nil)

type infoMemStore struct {
	syncmap.SyncMap[uint64, *statistic.Connection]
}

func newInfoMemStore() *infoMemStore { return &infoMemStore{} }

func (c *infoMemStore) Close() error { return nil }
