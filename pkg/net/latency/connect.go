package latency

import (
	"context"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// TCPConnect reports a completed Conn call separately from HTTPS and native
// tunnel state. Some protocols establish their final remote channel lazily.
func TCPConnect(ctx context.Context, p netapi.Proxy, target string) (time.Duration, error) {
	address, err := netapi.ParseAddress("tcp", target)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	conn, err := p.Conn(ctx, address)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

// HTTPSHead measures a verified complete HEAD response. It refuses redirects,
// keeps header size bounded and never downloads an unbounded response body.
func HTTPSHead(ctx context.Context, p netapi.Proxy, target string) (time.Duration, error) {
	return httpLatency(ctx, p, target, false, http.MethodHead, false)
}
