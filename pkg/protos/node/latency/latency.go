package latency

import (
	"context"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"time"

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

	for _, x := range []bool{false, true} {
		hc := &http.Client{
			Timeout: time.Second * 6,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					add, err := netapi.ParseAddress(network, addr)
					if err != nil {
						return nil, err
					}

					ip, err := netapi.Bootstrap.LookupIP(ctx, add.Hostname(), func(li *netapi.LookupIPOption) {
						if x {
							li.Mode = netapi.ResolverModePreferIPv6
						} else {
							li.Mode = netapi.ResolverModePreferIPv4
						}
					})
					if err != nil {
						return nil, err
					}

					return p.Conn(ctx, netapi.ParseIPAddrPort("tcp", ip[rand.IntN(len(ip))], add.Port()))
				},
			},
		}

		req, err := http.NewRequest("GET", l.Ip.GetUrl(), nil)
		if err != nil {
			slog.Error("new request error", slog.String("url", l.Ip.GetUrl()), slog.Any("err", err))
			continue
		}

		req.Header.Set("User-Agent", l.Ip.UserAgent)

		resp, err := hc.Do(req)
		if err != nil {
			slog.Error("get url error", slog.String("url", l.Ip.GetUrl()), slog.Any("err", err))
			continue
		}

		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			slog.Error("read body error", slog.Any("err", err))
			continue
		}

		if !x {
			reply.Ip.Ipv4 = string(data)
		} else {
			reply.Ip.Ipv6 = string(data)
		}
	}

	if reply.Ip.Ipv4 == "" && reply.Ip.Ipv6 == "" {
		return nil, io.EOF
	}

	return &Reply{
		Reply: reply,
	}, nil
}
