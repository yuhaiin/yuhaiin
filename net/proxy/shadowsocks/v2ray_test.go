package shadowsocks

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
)

func TestNewV2ray(t *testing.T) {

	s, err := NewShadowsocks("AEAD_CHACHA20_POLY1305", "your-password", "127.0.0.1", "8488", "v2ray", "host:baidu.com")
	if err != nil {
		t.Error(err)
	}

	DialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return s.Conn(addr)
	}
	tr := http.Transport{
		DialContext: DialContext,
	}
	newClient := &http.Client{Transport: &tr}
	res, err := newClient.Get("https://dns.rubyfish.cn/dns-query?name=www.google.com&type=aaaa")
	if err != nil {
		t.Error(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(body))
}
