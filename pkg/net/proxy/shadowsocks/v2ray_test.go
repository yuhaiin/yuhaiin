package shadowsocks

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/stretchr/testify/require"
)

func TestNewV2ray(t *testing.T) {
	p := simple.NewSimple("127.0.0.1", "1090")
	z, err := websocket.NewWebsocket("baidu.com", "", true, true, nil)(p)
	require.Nil(t, err)
	z, err = NewShadowsocks("AEAD_CHACHA20_POLY1305", "your-password", "127.0.0.1", "8488")(z)
	if err != nil {
		t.Error(err)
	}

	DialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return z.Conn(addr)
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
