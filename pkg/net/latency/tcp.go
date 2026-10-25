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
	tr := &http.Transport{
		DisableKeepAlives: true,
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
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	resp, err := (&http.Client{Transport: tr, Timeout: timeout}).Do(request)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return time.Since(start), nil
}
