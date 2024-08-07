package inbound

import (
	"context"

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

	l.store.Range(func(key string, v entry) bool {
		z, ok := current.Server.Inbounds[key]
		if !ok || !z.GetEnabled() {
			v.server.Close()
			l.store.Delete(key)
		}

		return true
	})

	for k, v := range current.Server.Inbounds {
		l.start(k, v)
	}
}

func (l *listener) start(key string, config *pl.Inbound) {
	if config == nil {
		return
	}

	v, ok := l.store.Load(key)
	if ok {
		if proto.Equal(v.config, config) {
			return
		}
		v.server.Close()
		l.store.Delete(key)
	}

	if !config.GetEnabled() {
		log.Debug("server disabled", "name", key)
		return
	}

	server, err := pl.Listen(config, l)
	if err != nil {
		log.Error("start server failed", "name", key, "err", err)
		return
	}

	l.store.Store(key, entry{config, server})
}

func (l *listener) Close() error {
	l.close()
	l.store.Range(func(key string, value entry) bool {
		log.Info("start close server", "name", key)
		defer log.Info("closed server", "name", key)
		value.server.Close()
		l.store.Delete(key)
		return true
	})
	return l.handler.Close()
}
