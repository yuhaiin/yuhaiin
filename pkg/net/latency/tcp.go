package latency

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func HTTP(p netapi.Proxy, target string) (time.Duration, error) {
	return HTTPWithInsecureSkipVerify(p, target, false)
}

// HTTPWithInsecureSkipVerify performs an HTTP GET, optionally skipping TLS
// certificate verification when explicitly requested by the node config.
func HTTPWithInsecureSkipVerify(p netapi.Proxy, target string, insecureSkipVerify bool) (time.Duration, error) {
	return HTTPWithContext(context.Background(), p, target, insecureSkipVerify)
}
func HTTPWithContext(ctx context.Context, p netapi.Proxy, target string, insecureSkipVerify bool) (time.Duration, error) {
	return httpLatency(ctx, p, target, insecureSkipVerify, http.MethodGet, true)
}
func httpLatency(ctx context.Context, p netapi.Proxy, target string, insecureSkipVerify bool, method string, redirect bool) (time.Duration, error) {
	tr := &http.Transport{
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 32 << 10,
		DisableCompression:     true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ad, err := netapi.ParseAddress(network, addr)
			if err != nil {
				return nil, fmt.Errorf("parse address failed: %w", err)
			}

			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			c, err := p.Conn(ctx, ad)
			if err != nil {
				return nil, err
			}

			return c, nil
		},
	}
	if insecureSkipVerify {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- gated by an explicit per-node setting.
		}
	}
	defer tr.CloseIdleConnections()

	start := time.Now()
	request, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Transport: tr, Timeout: timeout}
	if !redirect {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	resp, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if !redirect && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return 0, fmt.Errorf("probe endpoint redirect refused")
	}

	return time.Since(start), nil
}
