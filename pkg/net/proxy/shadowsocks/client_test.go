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
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

func TestConn(t *testing.T) {
	p, err := fixed.NewClient(node.Fixed_builder{
		Host: proto.String("127.0.0.1"),
		Port: proto.Int32(1080),
	}.Build(), nil)
	assert.NoError(t, err)
	z, err := websocket.NewClient(node.Websocket_builder{Host: proto.String("localhost:1090")}.Build(), p)
	assert.NoError(t, err)
	z, err = NewClient(node.Shadowsocks_builder{
		Method:   proto.String("aes-128-gcm"),
		Password: proto.String("test"),
	}.Build(),
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
	p, err := fixed.NewClient(node.Fixed_builder{
		Host: proto.String("127.0.0.1"),
		Port: proto.Int32(1090),
	}.Build(), nil)
	assert.NoError(t, err)
	s, err := NewClient(node.Shadowsocks_builder{
		Method:   proto.String("aes-128-gcm"),
		Password: proto.String("test"),
	}.Build(), p)
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
