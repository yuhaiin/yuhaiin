package latency

import (
	"context"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/subscr/shadowsocks"

	client "github.com/Asutorufa/yuhaiin/net/proxy/shadowsocks"
	"github.com/Asutorufa/yuhaiin/subscr"
)

func TestTcpLatency(t *testing.T) {
	n, err := subscr.GetNowNode()
	if err != nil {
		t.Error(err)
	}
	switch n.(type) {
	case *shadowsocks.Shadowsocks:
		x := n.(*shadowsocks.Shadowsocks)
		s, err := client.NewShadowsocks(x.Method, x.Password, x.Server, x.Port, x.Plugin, x.PluginOpt)
		if err != nil {
			t.Error(err)
		}
		testClient := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.Conn(addr)
		}
		t.Log(TcpLatency(testClient, "http://google.com/generate_204"))
	}
}
