package shadowsocks

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"net"
	"net/http"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/stretchr/testify/require"
)

func TestImplement(t *testing.T) {
	// make sure implement
	var _ proxy.Proxy = new(Shadowsocks)
}

func TestConn(t *testing.T) {
	p := simple.NewSimple("127.0.0.1", "1090")
	z, err := websocket.New(&node.PointProtocol_Websocket{Websocket: &node.Websocket{Host: "localhost:1090"}})(p)
	require.Nil(t, err)
	z, err = NewShadowsocks(
		&node.PointProtocol_Shadowsocks{
			Shadowsocks: &node.Shadowsocks{
				Method:   "aes-128-gcm",
				Password: "test",
				Server:   "127.0.0.1",
				Port:     "1090",
			},
		},
		// "v2ray",
		// "tls;cert=/mnt/data/program/go-shadowsocks/ca.crt;host=localhost:1090",
	)(z)
	if err != nil {
		t.Error(err)
		return
	}

	cc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				switch network {
				default:
					return net.Dial(network, addr)
				case "tcp":
					return z.Conn(addr)
				}
			},
		},
	}

	resp, err := cc.Get("http://ip.sb")
	require.Nil(t, err)

	data, err := ioutil.ReadAll(resp.Body)
	require.Nil(t, err)

	t.Log(string(data))
}

func TestUDPConn(t *testing.T) {
	p := simple.NewSimple("127.0.0.1", "1090")
	s, err := NewShadowsocks(
		&node.PointProtocol_Shadowsocks{
			Shadowsocks: &node.Shadowsocks{
				Method:   "aes-128-gcm",
				Password: "test",
				Server:   "127.0.0.1",
				Port:     "1090",
			},
		})(p)
	require.Nil(t, err)

	c, err := s.PacketConn("223.5.5.5:53")
	require.Nil(t, err)

	req := "ev4BAAABAAAAAAAAA3d3dwZnb29nbGUDY29tAAABAAE="

	data, err := base64.StdEncoding.DecodeString(req)
	require.Nil(t, err)
	x, err := c.WriteTo([]byte(data), nil)
	require.Nil(t, err)

	t.Log(x)

	y := make([]byte, 32*1024)

	x, addr, err := c.ReadFrom(y)
	require.Nil(t, err)
	t.Log(addr, y[:x])

}
