package vmess

import (
	"context"
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
