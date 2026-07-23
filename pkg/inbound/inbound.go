package inbound

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/auth"
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
	ctx context.Context

	dnsHandler netapi.DNSAgent
	authCenter *auth.Center

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

func WithDNSAgent(dnsHandler netapi.DNSAgent) Option {
	return func(l *Inbound) {
		l.dnsHandler = dnsHandler
	}
}

func WithAuthCenter(center *auth.Center) Option {
	return func(l *Inbound) { l.authCenter = center }
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

func (l *Inbound) SaveContract(req contract.Inbound) {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := req.ID
	if key == "" {
		key = req.Name
	}

	x, ok := l.store.Load(key)
	if ok {
		if x.contractConfig != nil && reflect.DeepEqual(*x.contractConfig, req) {
			return
		}

		l.store.Delete(key)

		if err := x.server.Close(); err != nil {
			log.Error("close server failed", "name", req.Name, "id", req.ID, "err", err)
		}
	}

	if !req.Enabled {
		return
	}

	server, err := listenContract(req, &handlerWrap{name: req.Name, handler: l}, l.authCenter)
	if err != nil {
		log.Error("start contract server failed", "name", req.Name, "id", req.ID, "err", err)
		return
	}

	log.Info("start contract server", "name", req.Name, "id", req.ID)
	l.store.Store(key, entry{contractConfig: &req, server: server})

	l.refreshInterfaces()
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

func (l *Inbound) Remove(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	x, ok := l.store.LoadAndDelete(name)
	if !ok {
		return
	}

	if err := x.server.Close(); err != nil {
		log.Error("close server failed", "name", name, "err", err)
	}

	l.refreshInterfaces()
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
	l.close()
	for k, v := range l.store.Range {
		log.Info("start close server", "name", k)
		if err := v.server.Close(); err != nil {
			log.Error("close server failed", "name", k, "err", err)
		}
		l.store.Delete(k)
		log.Info("closed server", "name", k)
	}
	return l.handler.Close()
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
