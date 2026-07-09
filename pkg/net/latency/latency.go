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

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const (
	defaultHTTPURL         = "https://www.gstatic.com/generate_204"
	defaultIPURL           = "http://ip.sb"
	defaultUDPResolverHost = "223.5.5.5:53"
	defaultDoQResolverHost = "dns.nextdns.io:853"
	defaultUDPTargetDomain = "www.google.com"
	defaultSTUNUDPHost     = "stun.nextcloud.com:3478"
	defaultSTUNTCPHost     = "stun.nextcloud.com:443"
)

func Latency(l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	if l.Type == "" {
		l.Type = "http"
	}
	if (l.Type == "http" || l.Type == "tcp") && l.URL == "" {
		l.URL = defaultHTTPURL
	}
	if l.Type == "ip" && l.URL == "" {
		l.URL = defaultIPURL
	}
	if (l.Type == "dns" || l.Type == "udp") && l.Host == "" {
		l.Host = defaultUDPResolverHost
	}
	if l.Type == "doq" && l.Host == "" {
		l.Host = defaultDoQResolverHost
	}
	if (l.Type == "dns" || l.Type == "udp" || l.Type == "doq") && l.TargetDomain == "" {
		l.TargetDomain = defaultUDPTargetDomain
	}
	if (l.Type == "stun" || l.Type == "stun_tcp") && l.Host == "" {
		if l.Type == "stun_tcp" || l.TCP {
			l.Host = defaultSTUNTCPHost
		} else {
			l.Host = defaultSTUNUDPHost
		}
	}
	switch l.Type {
	case "", "http", "tcp":
		return LatencyHttp(l, p)
	case "dns", "udp":
		return LatencyDns(l, p)
	case "doq":
		return LatencyDnsOverQuic(l, p)
	case "ip":
		return LatencyIp(l, p)
	case "stun", "stun_tcp":
		return LatencyStun(l, p)
	default:
		return contractnode.LatencyResponse{}, errors.ErrUnsupported
	}
}

func LatencyHttp(l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	t, err := HTTP(p, l.URL)
	return contractnode.LatencyResponse{OK: err == nil, LatencyMS: t.Milliseconds()}, err
}

func LatencyDns(l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	t, err := DNS(p, l.Host, l.TargetDomain)
	return contractnode.LatencyResponse{OK: err == nil, LatencyMS: t.Milliseconds()}, err
}

func LatencyDnsOverQuic(l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	t, err := DNSOverQuic(p, l.Host, l.TargetDomain)
	return contractnode.LatencyResponse{OK: err == nil, LatencyMS: t.Milliseconds()}, err
}

func LatencyIp(l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	if l.UserAgent == "" {
		l.UserAgent = "curl/7.54.1"
	}

	reply := contractnode.LatencyResponse{OK: true, IP: &contractnode.IPLatency{}}

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

			req, err := http.NewRequest("GET", l.URL, nil)
			if err != nil {
				log.Error("new request error", slog.String("url", l.URL), slog.Any("err", err))
				return
			}

			req.Header.Set("User-Agent", l.UserAgent)

			resp, err := hc.Do(req)
			if err != nil {
				log.Error("get url error", slog.String("url", l.URL), slog.Any("err", err))
				return
			}

			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Error("read body error", slog.Any("err", err))
				return
			}

			if !isIPv6 {
				reply.IP.IPv4 = string(data)
			} else {
				reply.IP.IPv6 = string(data)
			}
		}(isIPv6)
	}

	wg.Wait()

	if reply.IP.IPv4 == "" && reply.IP.IPv6 == "" {
		return contractnode.LatencyResponse{}, io.EOF
	}

	return reply, nil
}

func LatencyStun(l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	reply := contractnode.LatencyResponse{OK: true, STUN: &contractnode.STUNLatency{}}

	if l.Type == "stun_tcp" || l.TCP {
		mappedAddr, err := StunTCP(ctx, p, l.Host)
		if err != nil {
			return contractnode.LatencyResponse{}, err
		}
		reply.STUN.MappedAddress = mappedAddr
		return reply, nil
	}

	t, err := Stun(ctx, p, l.Host)
	if err != nil {
		return contractnode.LatencyResponse{}, err
	}

	reply.STUN.Mapping = t.MappingType.String()
	reply.STUN.Filtering = t.FilteringType.String()
	reply.STUN.MappedAddress = t.MappedAddr

	return reply, nil
}
