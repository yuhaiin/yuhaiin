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
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func ExampleNew() {
	simple := simple.New(&protocol.Protocol_Simple{
		Simple: &protocol.Simple{
			Host:             "127.0.0.1",
			Port:             1080,
			PacketConnDirect: false,
		},
	})
	ws := websocket.New(&protocol.Protocol_Websocket{
		Websocket: &protocol.Websocket{
			Host: "localhost",
		},
	})

	ss := New(&protocol.Protocol_Shadowsocks{
		Shadowsocks: &protocol.Shadowsocks{
			Method:   "aes-128-gcm",
			Password: "test",
		},
	})

	var err error
	var conn proxy.Proxy
	for _, wrap := range []protocol.WrapProxy{simple, ws, ss} {
		conn, err = wrap(conn)
		if err != nil {
			panic(err)
		}
	}
}

func TestConn(t *testing.T) {
	p := yerror.Must(simple.New(
		&protocol.Protocol_Simple{
			Simple: &protocol.Simple{
				Host: "127.0.0.1",
				Port: 1080,
			},
		})(nil))
	z, err := websocket.New(&protocol.Protocol_Websocket{Websocket: &protocol.Websocket{Host: "localhost:1090"}})(p)
	assert.NoError(t, err)
	z, err = New(
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
					ad, err := proxy.ParseAddress(proxy.PaseNetwork(network), addr)
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
	p := yerror.Must(simple.New(
		&protocol.Protocol_Simple{
			Simple: &protocol.Simple{
				Host: "127.0.0.1",
				Port: 1090,
			},
		})(nil))
	s, err := New(
		&protocol.Protocol_Shadowsocks{
			Shadowsocks: &protocol.Shadowsocks{
				Method:   "aes-128-gcm",
				Password: "test",
			},
		})(p)
	assert.NoError(t, err)

	ad, _ := proxy.ParseAddress(statistic.Type_udp, "223.5.5.5:53")
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
