package controller

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/net/latency"
	ssClient "github.com/Asutorufa/yuhaiin/net/proxy/shadowsocks/client"
	ssrClient "github.com/Asutorufa/yuhaiin/net/proxy/shadowsocksr/client"
	"github.com/Asutorufa/yuhaiin/subscr"
)

func Latency(group, mark string) (time.Duration, error) {
	n, err := GetOneNode(group, mark)
	if err != nil {
		return 0, err
	}
	var testClient func(ctx context.Context, network, addr string) (net.Conn, error)
	switch n.(type) {
	case *subscr.Shadowsocks:
		x := n.(*subscr.Shadowsocks)
		s, err := ssClient.NewShadowsocks(x.Method, x.Password, x.Server, x.Port, x.Plugin, x.PluginOpt)
		if err != nil {
			return 0, err
		}
		testClient = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.Conn(addr)
		}
	case *subscr.Shadowsocksr:
		n := n.(*subscr.Shadowsocksr)
		conn, err := ssrClient.NewShadowsocksrClient(
			n.Server, n.Port,
			n.Method,
			n.Password,
			n.Obfs,
			n.Obfsparam,
			n.Protocol,
			n.Protoparam,
		)
		if err != nil {
			return 0, err
		}
		testClient = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return conn.Conn(addr)
		}

	default:
		return 0, errors.New("not support")
	}
	return latency.TcpLatency(testClient, "https://www.google.com/generate_204")
}
