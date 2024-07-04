package shadowsocks

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func ExampleNew() {
	simple := simple.NewClient(&protocol.Protocol_Simple{
		Simple: &protocol.Simple{
			Host: "127.0.0.1",
			Port: 1080,
		},
	})
	ws := websocket.NewClient(&protocol.Protocol_Websocket{
		Websocket: &protocol.Websocket{
			Host: "localhost",
		},
	})

	ss := NewClient(&protocol.Protocol_Shadowsocks{
		Shadowsocks: &protocol.Shadowsocks{
			Method:   "aes-128-gcm",
			Password: "test",
		},
	})

	var err error
	var conn netapi.Proxy
	for _, wrap := range []point.WrapProxy{simple, ws, ss} {
		conn, err = wrap(conn)
		if err != nil {
			panic(err)
		}
	}
}

func TestConn(t *testing.T) {
	p, err := simple.NewClient(
		&protocol.Protocol_Simple{
			Simple: &protocol.Simple{
				Host: "127.0.0.1",
				Port: 1080,
			},
		})(nil)
	assert.NoError(t, err)
	z, err := websocket.NewClient(&protocol.Protocol_Websocket{Websocket: &protocol.Websocket{Host: "localhost:1090"}})(p)
	assert.NoError(t, err)
	z, err = NewClient(
		&protocol.Protocol_Shadowsocks{
			Shadowsocks: &protocol.Shadowsocks{
				Method:   "aes-128-gcm",
				Password: "test",
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
					return dialer.DialContext(ctx, network, addr)
				case "tcp":
					ad, err := netapi.ParseAddress(network, addr)
					if err != nil {
						return nil, fmt.Errorf("parse address failed: %v", err)
					}
					return z.Conn(ctx, ad)
				}
			},
		},
	}

	resp, err := cc.Get("http://ip.sb")
	assert.NoError(t, err)

	data, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	t.Log(string(data))
}

func TestUDPConn(t *testing.T) {
	p, err := simple.NewClient(
		&protocol.Protocol_Simple{
			Simple: &protocol.Simple{
				Host: "127.0.0.1",
				Port: 1090,
			},
		})(nil)
	assert.NoError(t, err)
	s, err := NewClient(
		&protocol.Protocol_Shadowsocks{
			Shadowsocks: &protocol.Shadowsocks{
				Method:   "aes-128-gcm",
				Password: "test",
			},
		})(p)
	assert.NoError(t, err)

	ad, _ := netapi.ParseAddress("udp", "223.5.5.5:53")
	c, err := s.PacketConn(context.TODO(), ad)
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
