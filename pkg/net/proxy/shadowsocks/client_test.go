package shadowsocks

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
)

func TestConn(t *testing.T) {
	s, err := NewShadowsocks(
		"aes-128-gcm",
		"test",
		"127.0.0.1",
		"1090",
		"v2ray",
		"tls;cert=/mnt/data/program/go-shadowsocks/ca.crt;host=localhost:1090",
	)
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
					return s.Conn(addr)
				}
			},
		},
	}

	resp, err := cc.Get("https://1.1.1.1")
	if err != nil {
		t.Error(err)
		return
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(string(data))
}

func TestUDPConn(t *testing.T) {
	s, err := NewShadowsocks(
		"aes-128-gcm",
		"test",
		"127.0.0.1",
		"1090",
		"",
		"",
	)
	if err != nil {
		t.Error(err)
		return
	}

	c, err := s.PacketConn("1.1.1.1:53")
	if err != nil {
		t.Error(err)
		return
	}

	req := "ev4BAAABAAAAAAAAA3d3dwZnb29nbGUDY29tAAABAAE="

	data, err := base64.StdEncoding.DecodeString(req)
	if err != nil {
		t.Error(err)
		return
	}

	x, err := c.WriteTo([]byte(data), nil)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(x)

	y := make([]byte, 32*1024)

	x, addr, err := c.ReadFrom(y)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(addr, y[:x])

}
