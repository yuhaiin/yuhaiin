package latency

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
)

func (l *Protocol) Latency(p netapi.Proxy) (*Reply, error) {
	ref := l.ProtoReflect()
	fields := ref.Descriptor().Oneofs().ByName("protocol")
	f := ref.WhichOneof(fields)
	if f == nil {
		return nil, errors.ErrUnsupported
	}

	v := ref.Get(f).Message().Interface()

	z, ok := v.(interface {
		Latency(p netapi.Proxy) (*Reply, error)
	})
	if !ok {
		return nil, fmt.Errorf("protocol %v not support", v)
	}

	return z.Latency(p)
}

func (l *Http) Latency(p netapi.Proxy) (*Reply, error) {
	t, err := latency.HTTP(p, l.GetUrl())
	return (&Reply_builder{Latency: durationpb.New(t)}).Build(), err
}

func (l *Dns) Latency(p netapi.Proxy) (*Reply, error) {
	t, err := latency.DNS(p, l.GetHost(), l.GetTargetDomain())
	return (&Reply_builder{Latency: durationpb.New(t)}).Build(), err
}

func (l *DnsOverQuic) Latency(p netapi.Proxy) (*Reply, error) {
	t, err := latency.DNSOverQuic(p, l.GetHost(), l.GetTargetDomain())
	return (&Reply_builder{Latency: durationpb.New(t)}).Build(), err
}

func (l *Ip) Latency(p netapi.Proxy) (*Reply, error) {
	if l.GetUserAgent() == "" {
		l.SetUserAgent("curl/7.54.1")
	}

	reply := &Reply_builder{
		Ip: &IpResponse{},
	}

	wg := sync.WaitGroup{}

	for _, isIPv6 := range []bool{false, true} {
		wg.Add(1)

		go func(isIPv6 bool) {
			defer wg.Done()
			hc := &http.Client{
				Timeout: time.Second * 6,
				Transport: &http.Transport{
					DisableKeepAlives: true,
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						add, err := netapi.ParseAddress(network, addr)
						if err != nil {
							return nil, err
						}

						ip, err := dialer.Bootstrap().LookupIP(ctx, add.Hostname(), func(li *netapi.LookupIPOption) {
							if isIPv6 {
								li.Mode = netapi.ResolverModePreferIPv6
							} else {
								li.Mode = netapi.ResolverModePreferIPv4
							}
						})
						if err != nil {
							return nil, err
						}

						return p.Conn(ctx, netapi.ParseIPAddr("tcp", ip[rand.IntN(len(ip))], add.Port()))
					},
				},
			}

			req, err := http.NewRequest("GET", l.GetUrl(), nil)
			if err != nil {
				log.Error("new request error", slog.String("url", l.GetUrl()), slog.Any("err", err))
				return
			}

			req.Header.Set("User-Agent", l.GetUserAgent())

			resp, err := hc.Do(req)
			if err != nil {
				log.Error("get url error", slog.String("url", l.GetUrl()), slog.Any("err", err))
				return
			}

			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Error("read body error", slog.Any("err", err))
				return
			}

			if !isIPv6 {
				reply.Ip.SetIpv4(string(data))
			} else {
				reply.Ip.SetIpv6(string(data))
			}
		}(isIPv6)
	}

	wg.Wait()

	if reply.Ip.GetIpv4() == "" && reply.Ip.GetIpv6() == "" {
		return nil, io.EOF
	}

	return reply.Build(), nil
}

func (l *Stun) Latency(p netapi.Proxy) (*Reply, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	replay := (&Reply_builder{
		Stun: &StunResponse{},
	}).Build()

	if l.GetTcp() {
		mappedAddr, err := latency.StunTCP(ctx, p, l.GetHost())
		if err != nil {
			return nil, err
		}
		replay.GetStun().SetMappedAddress(mappedAddr)
		return replay, nil
	}

	t, err := latency.Stun(ctx, p, l.GetHost())
	if err != nil {
		return nil, err
	}

	replay.GetStun().SetMapping(NatType(t.MappingType))
	replay.GetStun().SetFiltering(NatType(t.FilteringType))
	replay.GetStun().SetMappedAddress(t.MappedAddr)

	return replay, nil
}
