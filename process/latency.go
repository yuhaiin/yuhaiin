package process

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/net/latency"
	"github.com/Asutorufa/yuhaiin/net/proxy/shadowsocks/client"
	"github.com/Asutorufa/yuhaiin/subscr"
)

func Latency(group, mark string) (time.Duration, error) {
	n, err := subscr.GetOneNode(group, mark)
	if err != nil {
		return 0, err
	}
	switch n.(type) {
	case *subscr.Shadowsocks:
		x := n.(*subscr.Shadowsocks)
		s, err := client.NewShadowsocks(x.Method, x.Password, net.JoinHostPort(x.Server, x.Port), x.Plugin, x.PluginOpt)
		if err != nil {
			return 0, err
		}
		testClient := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.Conn(addr)
		}
		return latency.TcpLatency(testClient, "https://www.google.com/generate_204")
	case *subscr.Shadowsocksr:
		return latency.TCPConnectLatency(n.(*subscr.Shadowsocksr).Server, n.(*subscr.Shadowsocksr).Port)

	default:
		return 0, errors.New("not support")
	}
}
