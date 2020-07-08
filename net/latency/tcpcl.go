package latency

import (
	"net"
	"time"
)

// TCPDelay get once delay by tcp
func TCPConnectLatency(address, port string) (time.Duration, error) {
	timeNow := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, port), 3*time.Second)
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = conn.Close()
	}()
	return time.Since(timeNow), nil
}
