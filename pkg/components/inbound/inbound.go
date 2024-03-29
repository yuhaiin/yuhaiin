package inbound

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

func init() {
	pl.RegisterProtocolDeprecated(func(o *pl.Protocol_Http) (netapi.Accepter, error) {
		return pl.Listen(&pl.Inbound{
			Network: &pl.Inbound_Tcpudp{
				Tcpudp: &pl.Tcpudp{
					Host:    o.Http.Host,
					Control: pl.TcpUdpControl_disable_udp,
				},
			},
			Protocol: &pl.Inbound_Http{
				Http: o.Http,
			},
		})
	})
	pl.RegisterProtocolDeprecated(func(o *pl.Protocol_Mix) (netapi.Accepter, error) {
		return pl.Listen(&pl.Inbound{
			Network: &pl.Inbound_Tcpudp{
				Tcpudp: &pl.Tcpudp{
					Host: o.Mix.Host,
				},
			},
			Protocol: &pl.Inbound_Mix{
				Mix: o.Mix,
			},
		})
	})
	pl.RegisterProtocolDeprecated(func(o *pl.Protocol_Socks4A) (netapi.Accepter, error) {
		return pl.Listen(&pl.Inbound{
			Network: &pl.Inbound_Tcpudp{
				Tcpudp: &pl.Tcpudp{
					Host:    o.Socks4A.Host,
					Control: pl.TcpUdpControl_disable_udp,
				},
			},
			Protocol: &pl.Inbound_Socks4A{
				Socks4A: o.Socks4A,
			},
		})
	})
	pl.RegisterProtocolDeprecated(func(o *pl.Protocol_Socks5) (netapi.Accepter, error) {
		o.Socks5.Udp = true
		return pl.Listen(&pl.Inbound{
			Network: &pl.Inbound_Tcpudp{
				Tcpudp: &pl.Tcpudp{
					Host: o.Socks5.Host,
				},
			},
			Protocol: &pl.Inbound_Socks5{
				Socks5: o.Socks5,
			},
		})
	})
	pl.RegisterProtocolDeprecated(func(o *pl.Protocol_Tun) (netapi.Accepter, error) {
		return tun.NewTun(&pl.Inbound_Tun{Tun: o.Tun})(nil)
	})
	pl.RegisterProtocolDeprecated(func(o *pl.Protocol_Yuubinsya) (netapi.Accepter, error) {
		inbound := &pl.Inbound{
			Network: &pl.Inbound_Tcpudp{
				Tcpudp: &pl.Tcpudp{
					Host:    o.Yuubinsya.Host,
					Control: pl.TcpUdpControl_disable_udp,
				},
			},
			Protocol: &pl.Inbound_Yuubinsya{
				Yuubinsya: o.Yuubinsya,
			},
		}

		switch p := o.Yuubinsya.Protocol.(type) {
		case *pl.Yuubinsya_Normal:

		case *pl.Yuubinsya_Tls:
			inbound.Transport = append(inbound.Transport, &pl.Transport{
				Transport: &pl.Transport_Tls{
					Tls: p.Tls,
				},
			})
		case *pl.Yuubinsya_Quic:
			inbound.Network = &pl.Inbound_Quic{
				Quic: &pl.Quic2{
					Host: o.Yuubinsya.Host,
					Tls:  p.Quic.GetTls(),
				},
			}

		case *pl.Yuubinsya_Websocket:
			if p.Websocket.Tls != nil {
				inbound.Transport = append(inbound.Transport, &pl.Transport{
					Transport: &pl.Transport_Tls{
						Tls: &pl.Tls{
							Tls: p.Websocket.Tls,
						},
					},
				})
			}
			inbound.Transport = append(inbound.Transport,
				&pl.Transport{
					Transport: &pl.Transport_Websocket{
						Websocket: p.Websocket,
					},
				})
		case *pl.Yuubinsya_Grpc:

			if p.Grpc.Tls != nil {
				inbound.Transport = append(inbound.Transport, &pl.Transport{
					Transport: &pl.Transport_Tls{
						Tls: &pl.Tls{
							Tls: p.Grpc.Tls,
						},
					},
				})
			}
			inbound.Transport = append(inbound.Transport,
				&pl.Transport{
					Transport: &pl.Transport_Grpc{
						Grpc: p.Grpc,
					},
				})
		case *pl.Yuubinsya_Http2:

			if p.Http2.Tls != nil {
				inbound.Transport = append(inbound.Transport, &pl.Transport{
					Transport: &pl.Transport_Tls{
						Tls: &pl.Tls{
							Tls: p.Http2.Tls,
						},
					},
				})
			}
			inbound.Transport = append(inbound.Transport,
				&pl.Transport{
					Transport: &pl.Transport_Http2{
						Http2: p.Http2,
					},
				})

		case *pl.Yuubinsya_Reality:
			inbound.Transport = append(inbound.Transport, &pl.Transport{
				Transport: &pl.Transport_Reality{
					Reality: p.Reality,
				},
			})
		}

		if o.Yuubinsya.Mux {
			inbound.Transport = append(inbound.Transport, &pl.Transport{
				Transport: &pl.Transport_Mux{
					Mux: &pl.Mux{},
				},
			})
		}

		return pl.Listen(inbound)
	})
}

type store struct {
	config proto.Message
	server netapi.Accepter
}

type listener struct {
	store syncmap.SyncMap[string, store]

	handler *handler

	ctx   context.Context
	close context.CancelFunc

	tcpChannel chan *netapi.StreamMeta
	udpChannel chan *netapi.Packet

	hijackDNS bool
	fakeip    bool
}

func NewListener(dnsHandler netapi.DNSHandler, dialer netapi.Proxy) *listener {
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
					log.Error("tcp server handle DnsHijacking failed", "err", err)
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
						ctx = context.WithValue(l.ctx, netapi.ForceFakeIP{}, true)
					}

					err := l.handler.dnsHandler.Do(ctx, packet.Payload, func(b []byte) error {
						_, err := packet.WriteBack(b, packet.Dst)
						return err
					})
					if err != nil {
						log.Error("udp server handle DnsHijacking failed", "err", err)
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

	l.store.Range(func(key string, v store) bool {
		var close bool = true
		if strings.HasPrefix(key, "server-") {
			z1, ok1 := current.Server.Servers[strings.TrimPrefix(key, "server-")]
			close = !ok1 || !z1.Enabled
		} else if strings.HasPrefix(key, "inbound-") {
			z2, ok2 := current.Server.Inbounds[strings.TrimPrefix(key, "inbound-")]
			close = !ok2 || !z2.Enabled
		}

		if close {
			v.server.Close()
			l.store.Delete(key)
		}
		return true
	})

	start := func(name string, enabled bool, config proto.Message, start func() (netapi.Accepter, error)) {
		err := l.start(name, enabled, config, start)
		if err != nil {
			if errors.Is(err, errServerDisabled) {
				log.Debug(err.Error())
			} else {
				log.Error(fmt.Sprintf("start %s failed", name), "err", err)
			}
		}
	}

	for k, v := range current.Server.Servers {
		start("server-"+k, v.Enabled, v,
			func() (netapi.Accepter, error) { return pl.CreateServer(v.Protocol) })

	}

	for k, v := range current.Server.Inbounds {
		start("inbound-"+k, v.Enabled, v,
			func() (netapi.Accepter, error) { return pl.Listen(v) })

	}

}

var errServerDisabled = errors.New("disabled")

func (l *listener) start(name string, enabled bool, config proto.Message, start func() (netapi.Accepter, error)) error {
	v, ok := l.store.Load(name)
	if ok {
		if proto.Equal(v.config, config) {
			return nil
		}
		v.server.Close()
		l.store.Delete(name)
	}

	if !enabled {
		return fmt.Errorf("server %s %w", name, errServerDisabled)
	}

	server, err := start()
	if err != nil {
		return fmt.Errorf("create server %s failed: %w", name, err)
	}

	l.startForward(server)

	l.store.Store(name, store{config, server})
	return nil
}

func (l *listener) startForward(server netapi.Accepter) {
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
}

func (l *listener) Close() error {
	l.close()
	l.store.Range(func(key string, value store) bool {
		log.Info("start close server", "name", key)
		defer log.Info("closed server", "name", key)
		value.server.Close()
		l.store.Delete(key)
		return true
	})
	return l.handler.Close()
}
