package inbound

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/set"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

type entry struct {
	config *pl.Inbound
	server netapi.Accepter
}

var _ netapi.Handler = (*Inbound)(nil)

type Inbound struct {
	ctx context.Context

	handler *handler

	close context.CancelFunc

	// udpChannel cache channel for udp
	// the nat table is already use ringbuffer. so here just use buffer channel
	udpChannel chan *netapi.Packet

	store syncmap.SyncMap[string, entry]

	mu sync.RWMutex

	hijackDNS atomic.Bool
	fakeip    atomic.Bool

	interfaces     *set.Set[string]
	interfacesLock sync.RWMutex
}

func NewInbound(dnsHandler netapi.DNSServer, dialer netapi.Proxy) *Inbound {
	ctx, cancel := context.WithCancel(context.Background())

	l := &Inbound{
		handler:    NewHandler(dialer, dnsHandler),
		ctx:        ctx,
		close:      cancel,
		interfaces: set.NewSet[string](),
		udpChannel: make(chan *netapi.Packet, configuration.UDPChannelBufferSize),
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
	if !meta.DnsRequest && !l.shouldHijackDNS(meta.Address.Port()) {
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

	err := l.handler.dnsHandler.DoStream(l.ctx, &netapi.DNSStreamRequest{
		Conn:        meta.Src,
		ForceFakeIP: l.fakeip.Load(),
	})
	if err != nil {
		log.Select(netapi.LogLevel(err)).Print("tcp server handle DnsHijacking", "msg", err)
	}
}

func (l *Inbound) HandlePacket(packet *netapi.Packet) {
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

	if !packet.IsDNSRequest() && !l.shouldHijackDNS(packet.Dst().Port()) {
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

	err := l.handler.dnsHandler.Do(l.ctx, dnsReq)
	if err != nil {
		log.Select(netapi.LogLevel(err)).Print("udp server handle DnsHijacking", "msg", err)
	}
}

func (l *Inbound) Save(req *pl.Inbound) {
	l.mu.Lock()
	defer l.mu.Unlock()

	x, ok := l.store.Load(req.GetName())
	if ok {
		if proto.Equal(x.config, req) {
			return
		}

		l.store.Delete(req.GetName())

		if err := x.server.Close(); err != nil {
			log.Error("close server failed", "name", req.GetName(), "err", err)
		}
	}

	if !req.GetEnabled() {
		return
	}

	server, err := register.Listen(req, &handlerWrap{name: req.GetName(), handler: l})
	if err != nil {
		log.Error("start server failed", "name", req.GetName(), "err", err)
		return
	}

	log.Info("start server", "name", req.GetName())
	l.store.Store(req.GetName(), entry{req, server})

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
}

func (l *Inbound) SetHijackDnsFakeip(fakeip bool) {
	l.fakeip.Store(fakeip)
}

func (l *Inbound) SetSniff(sniff bool) {
	l.handler.sniffer.SetEnabled(sniff)
}

func (l *Inbound) Close() error {
	l.close()
	for k, v := range l.store.Range {
		log.Info("start close server", "name", k)
		v.server.Close()
		l.store.Delete(k)
		log.Info("closed server", "name", k)
	}
	return l.handler.Close()
}

type handlerWrap struct {
	name    string
	handler *Inbound
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
