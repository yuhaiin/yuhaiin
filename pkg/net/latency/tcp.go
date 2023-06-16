package latency

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
)

func HTTP(p proxy.Proxy, target string) (time.Duration, error) {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ad, err := proxy.ParseAddress(proxy.PaseNetwork(network), addr)
			if err != nil {
				return nil, fmt.Errorf("parse address failed: %w", err)
			}
			return p.Conn(ctx, ad)
		},
	}
	defer tr.CloseIdleConnections()

	start := time.Now()
	resp, err := (&http.Client{Transport: tr}).Get(target)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return time.Since(start), nil
}
