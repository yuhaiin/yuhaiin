package latency

import (
	"context"
	"net"
	"net/http"
	"time"
)

func TcpLatency(dialContext func(context.Context, string, string) (net.Conn, error), target string) (time.Duration, error) {
	timeNow := time.Now()
	_, err := (&http.Client{Transport: &http.Transport{DialContext: dialContext}, Timeout: 3 * time.Second}).Get(target)
	if err != nil {
		return 0, err
	}
	return time.Since(timeNow), nil
}
