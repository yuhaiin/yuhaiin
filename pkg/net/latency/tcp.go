package latency

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

func HTTP(p proxy.Proxy, target string) (time.Duration, error) {
	start := time.Now()
	_, err := (&http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ad, err := proxy.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %v", err)
				}
				return p.Conn(ad)
			},
		},
		Timeout: 3 * time.Second,
	}).Get(target)
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
