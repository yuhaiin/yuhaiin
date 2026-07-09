package shadowsocks

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestConn(t *testing.T) {
	t.Skip("requires a local shadowsocks/websocket server and external ip.sb access")

	p, err := fixed.NewClient(fixed.Config{Host: "127.0.0.1", Port: int32(1080)}, nil)
	assert.NoError(t, err)
	z, err := websocket.NewClient(websocket.Config{Host: "localhost:1090"}, p)
	assert.NoError(t, err)
	z, err = NewClient(Config{
		Method:   "aes-128-gcm",
		Password: "test",
	},
		// "v2ray",
		// "tls;cert=/mnt/data/program/go-shadowsocks/ca.crt;host=localhost:1090",
		z)
	if err != nil {
		t.Error(err)
		return
	}

	cc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				ap, err := netip.ParseAddrPort(addr)
				if err != nil {
					return nil, err
				}

				switch network {
				default:
					return dialer.DialTCPContext(ctx, ap)
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
	t.Skip("requires a local shadowsocks server and external DNS access")

	p, err := fixed.NewClient(fixed.Config{Host: "127.0.0.1", Port: int32(1090)}, nil)
	assert.NoError(t, err)
	s, err := NewClient(Config{
		Method:   "aes-128-gcm",
		Password: "test",
	}, p)
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
