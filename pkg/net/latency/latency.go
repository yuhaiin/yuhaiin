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

type LatencyOptions struct {
	InsecureSkipVerify bool
}

func Latency(l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	return LatencyWithOptions(l, p, LatencyOptions{})
}

func LatencyWithOptions(l contractnode.LatencyRequest, p netapi.Proxy, options LatencyOptions) (contractnode.LatencyResponse, error) {
	return LatencyWithContext(context.Background(), l, p, options)
}

// LatencyWithContext binds every network phase to the caller, allowing shared
// scheduler jobs to stop promptly on configuration changes and node deletion.
func LatencyWithContext(ctx context.Context, l contractnode.LatencyRequest, p netapi.Proxy, options LatencyOptions) (contractnode.LatencyResponse, error) {
	if err := ctx.Err(); err != nil {
		return contractnode.LatencyResponse{}, err
	}
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
		t, err := HTTPWithContext(ctx, p, l.URL, options.InsecureSkipVerify)
		return contractnode.LatencyResponse{OK: err == nil, LatencyMS: t.Milliseconds()}, err
	case "dns", "udp":
		t, err := DNSWithContext(ctx, p, l.Host, l.TargetDomain)
		return contractnode.LatencyResponse{OK: err == nil, LatencyMS: t.Milliseconds()}, err
	case "doq":
		t, err := DNSOverQuicWithContext(ctx, p, l.Host, l.TargetDomain)
		return contractnode.LatencyResponse{OK: err == nil, LatencyMS: t.Milliseconds()}, err
	case "ip":
		return latencyIPWithContext(ctx, l, p)
	case "stun", "stun_tcp":
		return latencySTUNWithContext(ctx, l, p)
	default:
		return contractnode.LatencyResponse{}, errors.ErrUnsupported
	}
}

func LatencyHttp(l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	return latencyHTTP(l, p, false)
}

func latencyHTTP(l contractnode.LatencyRequest, p netapi.Proxy, insecureSkipVerify bool) (contractnode.LatencyResponse, error) {
	t, err := HTTPWithInsecureSkipVerify(p, l.URL, insecureSkipVerify)
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
	return latencyIPWithContext(context.Background(), l, p)
}
func latencyIPWithContext(ctx context.Context, l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	if l.UserAgent == "" {
		l.UserAgent = "curl/7.54.1"
	}

	reply := contractnode.LatencyResponse{OK: true, IP: &contractnode.IPLatency{}}

	wg := sync.WaitGroup{}
	families := []bool{false, true}
	if configured, ok := p.(interface{ IPVersion() contractnode.IPVersion }); ok {
		switch configured.IPVersion() {
		case contractnode.IPVersionIPv4:
			families = []bool{false}
		case contractnode.IPVersionIPv6:
			families = []bool{true}
		}
	}

	for _, isIPv6 := range families {
		wg.Go(func() {
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

			req, err := http.NewRequestWithContext(ctx, "GET", l.URL, nil)
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

			data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
			resp.Body.Close()
			if err != nil {
				log.Error("read body error", slog.Any("err", err))
				return
			}

			if len(data) > 4096 {
				return
			}
			if !isIPv6 {
				reply.IP.IPv4 = string(data)
			} else {
				reply.IP.IPv6 = string(data)
			}
		})
	}

	wg.Wait()

	if err := ctx.Err(); err != nil {
		return contractnode.LatencyResponse{}, err
	}
	if reply.IP.IPv4 == "" && reply.IP.IPv6 == "" {
		return contractnode.LatencyResponse{}, io.EOF
	}

	return reply, nil
}

func LatencyStun(l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	return latencySTUNWithContext(context.Background(), l, p)
}
func latencySTUNWithContext(ctx context.Context, l contractnode.LatencyRequest, p netapi.Proxy) (contractnode.LatencyResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
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
