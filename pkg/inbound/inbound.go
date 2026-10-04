package inbound

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type entry struct {
	contractConfig *contract.Inbound
	server         netapi.Accepter
}

var _ netapi.Handler = (*Inbound)(nil)

type Inbound struct {
	fakeIPSource        FakeIPRangeSource
	fakeIPRanges        [2]netip.Prefix
	unsubscribeFakeIP   func()
	closed              bool
	pendingRouteCleanup []netapi.Accepter
	ctx                 context.Context

	dnsHandler netapi.DNSAgent

	handler *handler

	close context.CancelFunc

	// udpChannel cache channel for udp
	// the nat table is already use ringbuffer. so here just use buffer channel
	udpChannel chan *netapi.Packet

	interfaces *set.Set[string]

	store syncmap.SyncMap[string, entry]

	mu sync.RWMutex

	interfacesLock sync.RWMutex

	hijackDNS atomic.Bool
	fakeip    atomic.Bool
}

type Option func(*Inbound)

// FakeIPRangeSource publishes the active pools rather than persisted settings.
type FakeIPRangeSource interface {
	SubscribeFakeIPRanges(func([2]netip.Prefix) error) (func(), error)
}

func WithFakeIPRangeSource(source FakeIPRangeSource) Option {
	return func(l *Inbound) { l.fakeIPSource = source }
}

// UpdateFakeIPRanges keeps the runtime snapshot and updates active TUN routes
// without modifying the stored inbound configuration or rebuilding listeners.
func (l *Inbound) UpdateFakeIPRanges(ranges [2]netip.Prefix) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.fakeIPRanges = ranges
	result := l.retryRouteCleanup()
	for _, entry := range l.store.Range {
		config := entry.contractConfig
		if config == nil || config.Protocol.Tun == nil || !config.Protocol.Tun.AutoFakeIPRoute {
			continue
		}
		if updater, ok := entry.server.(interface{ UpdateFakeIPRanges([2]netip.Prefix) error }); ok {
			if err := updater.UpdateFakeIPRanges(ranges); err != nil {
				err = fmt.Errorf("update FakeIP routes for TUN %q: %w", config.Name, err)
				log.Error("update TUN FakeIP routes failed", "err", err)
				result = errors.Join(result, err)
			}
		}
	}
	return result
}

// Keep failed TUN cleanup reachable after its inbound is removed so subsequent
// saves, range notifications, and repeated Close can retry it.
func (l *Inbound) closeServer(server netapi.Accepter) error {
	err := server.Close()
	if err != nil {
		if _, ok := server.(interface{ UpdateFakeIPRanges([2]netip.Prefix) error }); ok {
			l.pendingRouteCleanup = append(l.pendingRouteCleanup, server)
		}
	}
	return err
}

func (l *Inbound) retryRouteCleanup() error {
	pending := l.pendingRouteCleanup
	l.pendingRouteCleanup = nil
	var result error
	for _, server := range pending {
		result = errors.Join(result, l.closeServer(server))
	}
	return result
}

func WithDNSAgent(dnsHandler netapi.DNSAgent) Option {
	return func(l *Inbound) {
		l.dnsHandler = dnsHandler
	}
}

func NewInbound(dialer netapi.Proxy, opts ...Option) *Inbound {
	ctx, cancel := context.WithCancel(context.Background())

	l := &Inbound{
		handler:    NewHandler(dialer),
		ctx:        ctx,
		close:      cancel,
		interfaces: set.NewSet[string](),
		udpChannel: make(chan *netapi.Packet, configuration.UDPChannelBufferSize),
	}

	for _, opt := range opts {
		opt(l)
	}

	if l.fakeIPSource != nil {
		var err error
		l.unsubscribeFakeIP, err = l.fakeIPSource.SubscribeFakeIPRanges(l.UpdateFakeIPRanges)
		if err != nil {
			log.Error("subscribe TUN FakeIP routes failed", "err", err)
		}
	}

	l.hijackDNS.Store(true)
	l.fakeip.Store(true)

	go l.loopudp()

	return l
}

func (l *Inbound) shouldHijackDNS(port uint16) bool {
	return l.hijackDNS.Load() && port == 53
}

func (l *Inbound) HandleStream(meta *netapi.StreamMeta) {
	metrics.Counter.AddStreamRequest()

	if (!meta.DnsRequest && !l.shouldHijackDNS(meta.Address.Port())) || l.dnsHandler == nil {
		store := netapi.WithContext(l.ctx)
		store.Source = meta.Source
		store.Destination = meta.Destination
		if meta.Inbound != nil {
			store.SetInbound(meta.Inbound)
		}
		store.SetInboundName(meta.InboundName)
		l.handler.Stream(store, meta)
		return
	}

	err := l.dnsHandler.DoStream(l.ctx, &netapi.DNSStreamRequest{
		Conn:        meta.Src,
		ForceFakeIP: l.fakeip.Load(),
	})
	if err != nil {
		log.Select(netapi.LogLevel(err)).Print("tcp server handle DnsHijacking", "msg", err)
	}
}

func (l *Inbound) HandlePacket(packet *netapi.Packet) {
	metrics.Counter.AddPacketRequest()

	select {
	case l.udpChannel <- packet:
	case <-l.ctx.Done():
		packet.DecRef()
	}
}

func (l *Inbound) HandlePing(packet *netapi.PingMeta) {
	ctx, cancel := context.WithTimeout(l.ctx, time.Second*3)
	defer cancel()
	store := netapi.WithContext(ctx)
	store.Source = packet.Source
	store.Destination = packet.Destination
	store.SetInboundName(packet.InboundName)
	store.ConnOptions().SetIsUdp(true)
	l.handler.Ping(store, packet)
}

func (l *Inbound) loopudp() {
	for {
		select {
		case <-l.ctx.Done():
			return
		case packet := <-l.udpChannel:
			l.handlePacket(packet)
		}
	}
}

func (l *Inbound) handlePacket(packet *netapi.Packet) {
	defer packet.DecRef()

	if (!packet.IsDNSRequest() && !l.shouldHijackDNS(packet.Dst().Port())) || l.dnsHandler == nil {
		// we only use [netapi.Context] at new PacketConn instead of every packet
		// so here just pass [l.ctx]
		l.handler.Packet(l.ctx, packet)
		return
	}

	dnsReq := &netapi.DNSRawRequest{
		Question: packet,
		WriteBack: func(b []byte) error {
			_, err := packet.WriteBack(b, packet.Dst())
			return err
		},
		ForceFakeIP: l.fakeip.Load(),
	}

	if err := l.dnsHandler.DoDatagram(l.ctx, dnsReq); err != nil {
		log.Select(netapi.LogLevel(err)).Print("udp server handle DnsHijacking", "msg", err)
	}
}

func (l *Inbound) SaveContract(req contract.Inbound) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return errors.New("inbound runtime is closed")
	}

	if err := l.retryRouteCleanup(); err != nil {
		return err
	}
	defer l.refreshInterfaces()

	key := req.ID
	if key == "" {
		key = req.Name
	}

	x, ok := l.store.Load(key)
	if ok {
		if x.contractConfig != nil && reflect.DeepEqual(*x.contractConfig, req) {
			if req.Protocol.Tun != nil && req.Protocol.Tun.AutoFakeIPRoute {
				if updater, ok := x.server.(interface{ UpdateFakeIPRanges([2]netip.Prefix) error }); ok {
					return updater.UpdateFakeIPRanges(l.fakeIPRanges)
				}
			}
			return nil
		}

		l.store.Delete(key)

		if err := l.closeServer(x.server); err != nil {
			log.Error("close server failed", "name", req.Name, "id", req.ID, "err", err)
			return err
		}
	}

	if !req.Enabled {
		return nil
	}

	server, err := listenContract(req, &handlerWrap{name: req.Name, handler: l}, l.fakeIPRanges)
	if err != nil {
		log.Error("start contract server failed", "name", req.Name, "id", req.ID, "err", err)
		return err
	}

	log.Info("start contract server", "name", req.Name, "id", req.ID)
	l.store.Store(key, entry{contractConfig: &req, server: server})

	return nil
}

func (l *Inbound) refreshInterfaces() {
	l.interfacesLock.Lock()
	defer l.interfacesLock.Unlock()

	ifaces := set.NewSet[string]()
	for _, v := range l.store.Range {
		if v.server.Interface() != "" {
			ifaces.Push(v.server.Interface())
		}
	}

	l.interfaces = ifaces
}

func (l *Inbound) Interfaces() *set.Set[string] {
	l.interfacesLock.RLock()
	defer l.interfacesLock.RUnlock()

	return l.interfaces
}

func (l *Inbound) Remove(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := l.retryRouteCleanup()
	x, ok := l.store.LoadAndDelete(name)
	if !ok {
		return result
	}
	if err := l.closeServer(x.server); err != nil {
		log.Error("close server failed", "name", name, "err", err)
		result = errors.Join(result, err)
	}
	l.refreshInterfaces()
	return result
}

func (l *Inbound) SetHijackDnsFakeip(fakeip bool) {
	l.fakeip.Store(fakeip)
}

func (l *Inbound) SetHijackDns(enabled bool) {
	l.hijackDNS.Store(enabled)
}

func (l *Inbound) SetSniff(sniff bool) {
	l.handler.sniffer.SetEnabled(sniff)
}

func (l *Inbound) Close() error {
	// Cancel before acquiring mu: the source may be finishing a callback that needs mu.
	if l.unsubscribeFakeIP != nil {
		l.unsubscribeFakeIP()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return l.retryRouteCleanup()
	}
	l.closed = true
	result := l.retryRouteCleanup()
	l.close()
	for k, v := range l.store.Range {
		log.Info("start close server", "name", k)
		if err := l.closeServer(v.server); err != nil {
			log.Error("close server failed", "name", k, "err", err)
			result = errors.Join(result, err)
		}
		l.store.Delete(k)
		log.Info("closed server", "name", k)
	}
	l.refreshInterfaces()
	return errors.Join(result, l.handler.Close())
}

type handlerWrap struct {
	handler *Inbound
	name    string
}

func (h *handlerWrap) HandleStream(meta *netapi.StreamMeta) {
	meta.InboundName = h.name
	h.handler.HandleStream(meta)
}

func (h *handlerWrap) HandlePacket(packet *netapi.Packet) {
	netapi.WithInboundName(h.name)(packet)
	h.handler.HandlePacket(packet)
}

func (h *handlerWrap) HandlePing(packet *netapi.PingMeta) {
	packet.InboundName = h.name
	h.handler.HandlePing(packet)
}
