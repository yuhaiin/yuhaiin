package latency

import (
	"context"
	"net"
	"net/http"
	"time"
)

func TcpLatency(dialContext func(ctx context.Context, network, addr string) (net.Conn, error), target string) (time.Duration, error) {
	tr := http.Transport{
		DialContext: dialContext,
	}
	newClient := &http.Client{Transport: &tr, Timeout: 3 * time.Second}
	timeNow := time.Now()
	_, err := newClient.Get(target)
	if err != nil {
		return 0, err
	}
	return time.Since(timeNow), nil
}
