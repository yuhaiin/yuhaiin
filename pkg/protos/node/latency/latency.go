package latency

import (
	"context"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	sync "sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
)

type Latencier interface {
	Latency(netapi.Proxy) (*Reply, error)
}

func (l *Protocol_Http) Latency(p netapi.Proxy) (*Reply, error) {
	t, err := latency.HTTP(p, l.Http.GetUrl())
	return &Reply{
		Reply: &Reply_Latency{Latency: durationpb.New(t)},
	}, err
}

func (l *Protocol_Dns) Latency(p netapi.Proxy) (*Reply, error) {
	t, err := latency.DNS(p, l.Dns.GetHost(), l.Dns.GetTargetDomain())
	return &Reply{
		Reply: &Reply_Latency{Latency: durationpb.New(t)},
	}, err
}

func (l *Protocol_DnsOverQuic) Latency(p netapi.Proxy) (*Reply, error) {
	t, err := latency.DNSOverQuic(p, l.DnsOverQuic.Host, l.DnsOverQuic.TargetDomain)
	return &Reply{
		Reply: &Reply_Latency{Latency: durationpb.New(t)},
	}, err
}

func (l *Protocol_Ip) Latency(p netapi.Proxy) (*Reply, error) {
	if l.Ip.UserAgent == "" {
		l.Ip.UserAgent = "curl/7.54.1"
	}

	reply := &Reply_Ip{
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

						ip, err := dialer.Bootstrap.LookupIP(ctx, add.Hostname(), func(li *netapi.LookupIPOption) {
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

			req, err := http.NewRequest("GET", l.Ip.GetUrl(), nil)
			if err != nil {
				slog.Error("new request error", slog.String("url", l.Ip.GetUrl()), slog.Any("err", err))
				return
			}

			req.Header.Set("User-Agent", l.Ip.UserAgent)

			resp, err := hc.Do(req)
			if err != nil {
				slog.Error("get url error", slog.String("url", l.Ip.GetUrl()), slog.Any("err", err))
				return
			}

			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				slog.Error("read body error", slog.Any("err", err))
				return
			}

			if !isIPv6 {
				reply.Ip.Ipv4 = string(data)
			} else {
				reply.Ip.Ipv6 = string(data)
			}
		}(isIPv6)
	}

	wg.Wait()

	if reply.Ip.Ipv4 == "" && reply.Ip.Ipv6 == "" {
		return nil, io.EOF
	}

	return &Reply{
		Reply: reply,
	}, nil
}

func (l *Protocol_Stun) Latency(p netapi.Proxy) (*Reply, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	replay := &Reply{
		Reply: &Reply_Stun{
			Stun: &StunResponse{},
		},
	}

	if l.Stun.Tcp {
		mappedAddr, err := latency.StunTCP(ctx, p, l.Stun.GetHost())
		if err != nil {
			return nil, err
		}
		replay.GetStun().MappedAddress = mappedAddr
		return replay, nil
	}

	t, err := latency.Stun(ctx, p, l.Stun.GetHost())
	if err != nil {
		return nil, err
	}

	replay.GetStun().Mapping = NatType(t.MappingType)
	replay.GetStun().Filtering = NatType(t.FilteringType)
	replay.GetStun().MappedAddress = t.MappedAddr

	return replay, nil
}
