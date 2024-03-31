package inbound

import (
	"context"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

type key struct {
	name string
	old  bool
}

type entry struct {
	config *pl.Inbound
	server netapi.Accepter
}

type listener struct {
	store syncmap.SyncMap[key, entry]

	handler *handler

	ctx   context.Context
	close context.CancelFunc

	tcpChannel chan *netapi.StreamMeta
	udpChannel chan *netapi.Packet

	hijackDNS bool
	fakeip    bool
}

func NewListener(dnsHandler netapi.DNSServer, dialer netapi.Proxy) *listener {
	ctx, cancel := context.WithCancel(context.Background())

	l := &listener{
		handler:    NewHandler(dialer, dnsHandler),
		ctx:        ctx,
		close:      cancel,
		tcpChannel: make(chan *netapi.StreamMeta, 100),
		udpChannel: make(chan *netapi.Packet, 100),

		hijackDNS: true,
		fakeip:    true,
	}

	go l.tcp()
	go l.udp()

	return l
}

func (l *listener) tcp() {
	for {
		select {
		case <-l.ctx.Done():
			return
		case stream := <-l.tcpChannel:
			if stream.Address.Port().Port() == 53 && l.hijackDNS {
				err := l.handler.dnsHandler.HandleTCP(l.ctx, stream.Src)
				_ = stream.Src.Close()
				if err != nil {
					if errors.Is(err, netapi.ErrBlocked) {
						log.Debug("blocked", "msg", err)
					} else {
						log.Error("tcp server handle DnsHijacking failed", "err", err)
					}
				}
				continue
			}

			l.handler.Stream(l.ctx, stream)
		}
	}
}

func (l *listener) udp() {
	for {
		select {
		case <-l.ctx.Done():
			return
		case packet := <-l.udpChannel:
			if packet.Dst.Port().Port() == 53 && l.hijackDNS {
				go func() {
					ctx := l.ctx
					if l.fakeip {
						ctx = context.WithValue(ctx,
							netapi.ForceFakeIP{}, true)
					}

					err := l.handler.dnsHandler.Do(ctx, packet.Payload, func(b []byte) error {
						_, err := packet.WriteBack(b, packet.Dst)
						return err
					})
					if err != nil {
						if errors.Is(err, netapi.ErrBlocked) {
							log.Debug("blocked", "msg", err)
						} else {
							log.Error("udp server handle DnsHijacking failed", "err", err)
						}
					}
				}()

				continue
			}

			l.handler.Packet(l.ctx, packet)
		}
	}
}

func (l *listener) Update(current *pc.Setting) {
	// l.hijackDNS = current.Server.HijackDns
	l.fakeip = current.Server.HijackDnsFakeip

	l.store.Range(func(key key, v entry) bool {
		var z interface{ GetEnabled() bool }
		var ok bool
		if key.old {
			z, ok = current.Server.Servers[key.name]
		} else {
			z, ok = current.Server.Inbounds[key.name]
		}

		if !ok || !z.GetEnabled() {
			v.server.Close()
			l.store.Delete(key)
		}

		return true
	})

	for k, v := range current.Server.Servers {
		l.start(key{k, true}, v.ToInbound())
	}

	for k, v := range current.Server.Inbounds {
		l.start(key{k, false}, v)
	}
}

func (l *listener) start(key key, config *pl.Inbound) {
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

	server, err := pl.Listen(config)
	if err != nil {
		log.Error("start server failed", "name", key, "err", err)
		return
	}

	go func() {
		for {
			stream, err := server.AcceptStream()
			if err != nil {
				log.Error("accept stream failed", "err", err)
				return
			}

			select {
			case <-l.ctx.Done():
				return
			case l.tcpChannel <- stream:
			}
		}
	}()

	go func() {
		for {
			packet, err := server.AcceptPacket()
			if err != nil {
				log.Error("accept packet failed", "err", err)
				return
			}

			select {
			case <-l.ctx.Done():
				return
			case l.udpChannel <- packet:
			}
		}
	}()

	l.store.Store(key, entry{config, server})
}

func (l *listener) Close() error {
	l.close()
	l.store.Range(func(key key, value entry) bool {
		log.Info("start close server", "name", key)
		defer log.Info("closed server", "name", key)
		value.server.Close()
		l.store.Delete(key)
		return true
	})
	return l.handler.Close()
}
