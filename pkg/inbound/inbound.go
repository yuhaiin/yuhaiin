package inbound

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
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

	mu    sync.RWMutex
	store syncmap.SyncMap[string, entry]

	hijackDNS atomic.Bool
	fakeip    atomic.Bool

	// udpChannel cache channel for udp
	// the nat table is already use ringbuffer. so here just use buffer channel
	udpChannel chan *netapi.Packet
}

func NewInbound(dnsHandler netapi.DNSServer, dialer netapi.Proxy) *Inbound {
	ctx, cancel := context.WithCancel(context.Background())

	l := &Inbound{
		handler:    NewHandler(dialer, dnsHandler),
		ctx:        ctx,
		close:      cancel,
		udpChannel: make(chan *netapi.Packet, configuration.UDPChannelBufferSize),
	}

	l.hijackDNS.Store(true)
	l.fakeip.Store(true)

	go l.loopudp()

	return l
}

func (l *Inbound) isDNS(port uint16) bool {
	return l.hijackDNS.Load() && port == 53
}

func (l *Inbound) HandleStream(meta *netapi.StreamMeta) {
	go func() {
		if !l.isDNS(meta.Address.Port()) {
			store := netapi.WithContext(l.ctx)
			store.Source = meta.Source
			store.Destination = meta.Destination
			if meta.Inbound != nil {
				store.Inbound = meta.Inbound
			}
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
	}()
}

func (l *Inbound) HandlePacket(packet *netapi.Packet) {
	select {
	case l.udpChannel <- packet:
	case <-l.ctx.Done():
		packet.DecRef()
	}
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

	if !l.isDNS(packet.Dst.Port()) {
		// we only use [netapi.Context] at new PacketConn instead of every packet
		// so here just pass [l.ctx]
		l.handler.Packet(l.ctx, packet)
		return
	}

	dnsReq := &netapi.DNSRawRequest{
		Question: packet,
		WriteBack: func(b []byte) error {
			_, err := packet.WriteBack.WriteBack(b, packet.Dst)
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

	server, err := register.Listen(req, l)
	if err != nil {
		log.Error("start server failed", "name", req.GetName(), "err", err)
		return
	}

	log.Info("start server", "name", req.GetName())
	l.store.Store(req.GetName(), entry{req, server})

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

func (i *Inbound) SetSniff(sniff bool) {
	i.handler.sniffer.SetEnabled(sniff)
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
