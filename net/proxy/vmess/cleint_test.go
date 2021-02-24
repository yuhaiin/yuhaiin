package vmess

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
)

func TestNewVmess(t *testing.T) {
	v, err := NewVmess(
		"x.v2ray.com", 20004,
		"e70xxx12-4xxxf-xxxe-axx7-46a1xxxxxxxxf", "none", 2,
		"ws", "/", "www.xxx.com", false, "")
	if err != nil {
		t.Error(err)
		return
	}

	cc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return v.Conn(addr)
			},
		},
	}

	resp, err := cc.Get("https://www.youtube.com")
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

func TestNewUDPConn(t *testing.T) {
	v, err := NewVmess(
		"x.v2ray.com", 20004,
		"e70xxx12-4xxxf-xxxe-axx7-46a1xxxxxxxxf", "none", 2,
		"ws", "/", "www.xxx.com", false, "")
	if err != nil {
		t.Error(err)
		return
	}

	c, err := v.UDPConn("1.1.1.1:53")
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
	t.Log(addr, y)
}
