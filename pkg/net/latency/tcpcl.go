package latency

import (
	"context"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
)

// TCPDelay get once delay by tcp
func TCPConnectLatency(address, port string) (time.Duration, error) {
	timeNow := time.Now()
	ctx, cancel := context.WithTimeout(context.TODO(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, port))
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = conn.Close()
	}()
	return time.Since(timeNow), nil
}
