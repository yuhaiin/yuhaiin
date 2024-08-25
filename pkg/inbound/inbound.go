package inbound

import (
	"context"
	"iter"

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

	hijackDNS bool
	fakeip    bool
}

func NewListener(dnsHandler netapi.DNSServer, dialer netapi.Proxy) *listener {
	ctx, cancel := context.WithCancel(context.Background())

	l := &listener{
		handler: NewHandler(dialer, dnsHandler),
		ctx:     ctx,
		close:   cancel,

		hijackDNS: true,
		fakeip:    true,
	}

	return l
}

func (l *listener) HandleStream(stream *netapi.StreamMeta) {
	if !l.hijackDNS || stream.Address.Port() != 53 {
		l.handler.Stream(l.ctx, stream)
		return
	}

	go func() {
		ctx := netapi.WithContext(l.ctx)
		ctx.Resolver.ForceFakeIP = l.fakeip
		err := l.handler.dnsHandler.HandleTCP(ctx, stream.Src)
		_ = stream.Src.Close()
		if err != nil {
			log.Output(0, netapi.LogLevel(err), "tcp server handle DnsHijacking", "msg", err)
		}
	}()
}

func (l *listener) HandlePacket(packet *netapi.Packet) {
	defer packet.DecRef()

	if !l.hijackDNS || packet.Dst.Port() != 53 {
		l.handler.Packet(l.ctx, packet)
		return
	}

	packet.IncRef()
	go func() {
		defer packet.DecRef()

		ctx := netapi.WithContext(l.ctx)
		ctx.Resolver.ForceFakeIP = l.fakeip
		dnsReq := &netapi.DNSRawRequest{
			Question: packet.Payload,
			WriteBack: func(b []byte) error {
				_, err := packet.WriteBack.WriteBack(b, packet.Dst)
				return err
			},
		}
		err := l.handler.dnsHandler.Do(ctx, dnsReq)
		if err != nil {
			log.Output(0, netapi.LogLevel(err), "udp server handle DnsHijacking", "msg", err)
		}
	}()
}

func (l *listener) Update(current *pc.Setting) {
	// l.hijackDNS = current.Server.HijackDns
	l.fakeip = current.Server.HijackDnsFakeip
	l.handler.sniffyEnabled = current.GetServer().GetSniff().GetEnabled()

	for v := range l.diff(current.Server.Inbounds) {
		if v.Rmoved || v.Modif {
			v.Old.server.Close()
			l.store.Delete(v.Key)
		}

		if (v.Added || v.Modif) && v.New.GetEnabled() {
			server, err := pl.Listen(v.New, l)
			if err != nil {
				log.Error("start server failed", "name", v.Key, "err", err)
				continue
			}

			l.store.Store(v.Key, entry{v.New, server})
		}
	}
}

type Diff struct {
	Rmoved bool
	Added  bool
	Modif  bool

	Key string
	New *pl.Inbound
	Old entry
}

func (l *listener) diff(newInbounds map[string]*pl.Inbound) iter.Seq[Diff] {
	return func(f func(Diff) bool) {
		for k, v1 := range l.store.Range {
			z, ok := newInbounds[k]
			if !ok || !z.GetEnabled() {
				f(Diff{Rmoved: true, Key: k, Old: v1})
			}
		}

		for k, v2 := range newInbounds {
			if v2 == nil {
				continue
			}
			v1, ok := l.store.Load(k)
			if !ok {
				f(Diff{Added: true, Key: k, New: v2})
			} else if !proto.Equal(v1.config, v2) {
				f(Diff{Modif: true, Key: k, Old: v1, New: v2})
			}
		}
	}
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
