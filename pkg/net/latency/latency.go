package latency

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/types/known/durationpb"
)

func Latency(l *node.RequestProtocol, p netapi.Proxy) (*node.Reply, error) {
	switch l.WhichProtocol() {
	case node.RequestProtocol_Http_case:
		return LatencyHttp(l.GetHttp(), p)
	case node.RequestProtocol_Dns_case:
		return LatencyDns(l.GetDns(), p)
	case node.RequestProtocol_DnsOverQuic_case:
		return LatencyDnsOverQuic(l.GetDnsOverQuic(), p)
	case node.RequestProtocol_Ip_case:
		return LatencyIp(l.GetIp(), p)
	case node.RequestProtocol_Stun_case:
		return LatencyStun(l.GetStun(), p)
	default:
		return nil, errors.ErrUnsupported
	}
}

func LatencyHttp(l *node.HttpTest, p netapi.Proxy) (*node.Reply, error) {
	t, err := HTTP(p, l.GetUrl())
	return (&node.Reply_builder{Latency: durationpb.New(t)}).Build(), err
}

func LatencyDns(l *node.DnsTest, p netapi.Proxy) (*node.Reply, error) {
	t, err := DNS(p, l.GetHost(), l.GetTargetDomain())
	return (&node.Reply_builder{Latency: durationpb.New(t)}).Build(), err
}

func LatencyDnsOverQuic(l *node.DnsOverQuic, p netapi.Proxy) (*node.Reply, error) {
	t, err := DNSOverQuic(p, l.GetHost(), l.GetTargetDomain())
	return (&node.Reply_builder{Latency: durationpb.New(t)}).Build(), err
}

func LatencyIp(l *node.Ip, p netapi.Proxy) (*node.Reply, error) {
	if l.GetUserAgent() == "" {
		l.SetUserAgent("curl/7.54.1")
	}

	reply := &node.Reply_builder{
		Ip: &node.IpResponse{},
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

						ip, err := netapi.Bootstrap().LookupIP(ctx, add.Hostname(), func(li *netapi.LookupIPOption) {
							if isIPv6 {
								li.Mode = netapi.ResolverModePreferIPv6
							} else {
								li.Mode = netapi.ResolverModePreferIPv4
							}
						})
						if err != nil {
							return nil, err
						}

						return p.Conn(ctx, netapi.ParseIPAddr("tcp", ip.Rand(), add.Port()))
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

func LatencyStun(l *node.Stun, p netapi.Proxy) (*node.Reply, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	replay := (&node.Reply_builder{
		Stun: &node.StunResponse{},
	}).Build()

	if l.GetTcp() {
		mappedAddr, err := StunTCP(ctx, p, l.GetHost())
		if err != nil {
			return nil, err
		}
		replay.GetStun().SetMappedAddress(mappedAddr)
		return replay, nil
	}

	t, err := Stun(ctx, p, l.GetHost())
	if err != nil {
		return nil, err
	}

	replay.GetStun().SetMapping(node.NatType(t.MappingType))
	replay.GetStun().SetFiltering(node.NatType(t.FilteringType))
	replay.GetStun().SetMappedAddress(t.MappedAddr)

	return replay, nil
}
