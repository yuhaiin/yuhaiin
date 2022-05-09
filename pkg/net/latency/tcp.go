package latency

import (
	"context"
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
				return p.Conn(addr)
			},
		},
		Timeout: 3 * time.Second,
	}).Get(target)
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
