package inbound

import (
	"context"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

type entry struct {
	config *pl.Inbound
	server netapi.Accepter
}

var _ netapi.Handler = (*listener)(nil)

type listener struct {
	ctx context.Context

	handler *handler

	close context.CancelFunc

	store syncmap.SyncMap[string, entry]

	hijackDNS atomic.Bool
	fakeip    atomic.Bool

	udpChannel chan *netapi.Packet
}

func NewListener(dnsHandler netapi.DNSServer, dialer netapi.Proxy) *listener {
	ctx, cancel := context.WithCancel(context.Background())

	l := &listener{
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

func (l *listener) isHandleDNS(port uint16) bool {
	return l.hijackDNS.Load() && port == 53
}

func (l *listener) HandleStream(meta *netapi.StreamMeta) {
	go func() {
		ctx := netapi.WithContext(l.ctx)
		ctx.Source = meta.Source
		ctx.Destination = meta.Destination
		if meta.Inbound != nil {
			ctx.Inbound = meta.Inbound
		}

		if !l.isHandleDNS(meta.Address.Port()) {
			l.handler.Stream(ctx, meta)
			return
		}

		ctx.Resolver.ForceFakeIP = l.fakeip.Load()

		err := l.handler.dnsHandler.HandleTCP(ctx, meta.Src)
		_ = meta.Src.Close()
		if err != nil {
			log.Select(netapi.LogLevel(err)).Print("tcp server handle DnsHijacking", "msg", err)
		}
	}()
}

func (l *listener) HandlePacket(packet *netapi.Packet) {
	select {
	case l.udpChannel <- packet:
	case <-l.ctx.Done():
		packet.DecRef()
	}
}

func (l *listener) loopudp() {
	for {
		select {
		case <-l.ctx.Done():
			return
		case packet := <-l.udpChannel:
			l.handlePacket(packet)
		}
	}
}

func (l *listener) handlePacket(packet *netapi.Packet) {
	ctx := netapi.WithContext(l.ctx)
	ctx.Source = packet.Src
	ctx.Destination = packet.Dst

	if !l.isHandleDNS(packet.Dst.Port()) {
		l.handler.Packet(ctx, packet)
		packet.DecRef()
	} else {
		go func() {
			defer packet.DecRef()
			ctx.Resolver.ForceFakeIP = l.fakeip.Load()
			dnsReq := &netapi.DNSRawRequest{
				Question: packet.Payload,
				WriteBack: func(b []byte) error {
					_, err := packet.WriteBack.WriteBack(b, packet.Dst)
					return err
				},
			}
			err := l.handler.dnsHandler.Do(ctx, dnsReq)
			if err != nil {
				log.Select(netapi.LogLevel(err)).Print("udp server handle DnsHijacking", "msg", err)
			}
		}()
	}
}

func (l *listener) Update(current *pc.Setting) {
	// l.hijackDNS.Store(current.Server.HijackDns)
	l.fakeip.Store(current.Server.HijackDnsFakeip)
	l.handler.sniffyEnabled = current.GetServer().GetSniff().GetEnabled()

	diffs := l.diff(current.Server.Inbounds)

	for _, v := range append(diffs.Removed, diffs.Modified...) {
		v.Old.server.Close()
		l.store.Delete(v.Key)
	}

	for _, v := range append(diffs.Added, diffs.Modified...) {
		if v.New.GetEnabled() {
			server, err := pl.Listen(v.New, l)
			if err != nil {
				log.Error("start server failed", "name", v.Key, "err", err)
				continue
			}

			log.Info("start server", "name", v.Key)

			l.store.Store(v.Key, entry{v.New, server})
		}
	}
}

type Diff struct {
	Old entry
	New *pl.Inbound

	Key string
}

type Diffs struct {
	Removed  []Diff
	Added    []Diff
	Modified []Diff
}

func (l *listener) diff(newInbounds map[string]*pl.Inbound) Diffs {
	diffs := Diffs{}

	for k, v1 := range l.store.Range {
		z, ok := newInbounds[k]
		if !ok || !z.GetEnabled() {
			diffs.Removed = append(diffs.Removed, Diff{Key: k, Old: v1})
		}
	}

	for k, v2 := range newInbounds {
		if v2 == nil {
			continue
		}
		v1, ok := l.store.Load(k)
		if !ok {
			diffs.Added = append(diffs.Added, Diff{Key: k, New: v2})
		} else if !proto.Equal(v1.config, v2) {
			diffs.Modified = append(diffs.Modified, Diff{Key: k, Old: v1, New: v2})
		}
	}

	return diffs
}

func (l *listener) Close() error {
	l.close()
	for k, v := range l.store.Range {
		log.Info("start close server", "name", k)
		v.server.Close()
		l.store.Delete(k)
		log.Info("closed server", "name", k)
	}
	return l.handler.Close()
}
