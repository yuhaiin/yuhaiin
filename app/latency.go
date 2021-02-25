package app

import (
	"context"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/net/latency"
)

func Latency(group, mark string) (time.Duration, error) {
	conn, err := GetOneNodeConn(group, mark)
	if err != nil {
		return 0, err
	}
	return latency.TcpLatency(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return conn(addr)
	}, "https://www.google.com/generate_204")
}
