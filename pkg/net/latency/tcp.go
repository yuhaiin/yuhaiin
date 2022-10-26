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
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ad, err := proxy.ParseAddress(network, addr)
			if err != nil {
				return nil, fmt.Errorf("parse address failed: %v", err)
			}
			return p.Conn(ad)
		},
	}
	defer tr.CloseIdleConnections()

	start := time.Now()
	resp, err := (&http.Client{Transport: tr, Timeout: 4 * time.Second}).Get(target)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return time.Since(start), nil
}
