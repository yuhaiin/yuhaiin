package shadowsocks

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestImplement(t *testing.T) {
	// make sure implement
	var _ proxy.Proxy = new(Shadowsocks)
}

func TestConn(t *testing.T) {

	p := simple.NewSimple(proxy.ParseAddressSplit("tcp", "127.0.0.1", 1080), nil)
	z, err := websocket.New(&node.PointProtocol_Websocket{Websocket: &node.Websocket{Host: "localhost:1090"}})(p)
	assert.NoError(t, err)
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
					ad, err := proxy.ParseAddress(network, addr)
					if err != nil {
						return nil, fmt.Errorf("parse address failed: %v", err)
					}
					return z.Conn(ad)
				}
			},
		},
	}

	resp, err := cc.Get("http://ip.sb")
	assert.NoError(t, err)

	data, err := ioutil.ReadAll(resp.Body)
	assert.NoError(t, err)

	t.Log(string(data))
}

func TestUDPConn(t *testing.T) {
	p := simple.NewSimple(proxy.ParseAddressSplit("tcp", "127.0.0.1", 1090), nil)
	s, err := NewShadowsocks(
		&node.PointProtocol_Shadowsocks{
			Shadowsocks: &node.Shadowsocks{
				Method:   "aes-128-gcm",
				Password: "test",
				Server:   "127.0.0.1",
				Port:     "1090",
			},
		})(p)
	assert.NoError(t, err)

	ad, _ := proxy.ParseAddress("udp", "223.5.5.5:53")
	c, err := s.PacketConn(ad)
	assert.NoError(t, err)

	req := "ev4BAAABAAAAAAAAA3d3dwZnb29nbGUDY29tAAABAAE="

	data, err := base64.StdEncoding.DecodeString(req)
	assert.NoError(t, err)
	x, err := c.WriteTo([]byte(data), nil)
	assert.NoError(t, err)

	t.Log(x)

	y := make([]byte, 32*1024)

	x, addr, err := c.ReadFrom(y)
	assert.NoError(t, err)
	t.Log(addr, y[:x])

}
