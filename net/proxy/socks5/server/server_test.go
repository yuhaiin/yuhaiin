package socks5server

import (
	"net"
	"testing"

	"github.com/shadowsocks/go-shadowsocks2/socks"

	socks5client "github.com/Asutorufa/yuhaiin/net/proxy/socks5/client"
)

func TestResolveAddr(t *testing.T) {
	x, err := socks5client.ParseAddr("www.baidu.com:443")
	if err != nil {
		t.Error(err)
	}
	t.Log(ResolveAddr(x))
	x, err = socks5client.ParseAddr("127.0.0.1:443")
	if err != nil {
		t.Error(err)
	}
	t.Log(x[0], x[1], x[2], x[3], x[4], x[3:], x[:3], x[:])
	t.Log(ResolveAddr(x))
	x, err = socks5client.ParseAddr("ff::ff:443")
	if err != nil {
		t.Error(err)
	}
	t.Log(ResolveAddr(x))

	addr, err := net.ResolveIPAddr("ip", "www.baidu.com")
	if err != nil {
		t.Error(err)
	}
	t.Log(addr.IP)
}

func TestParse(t *testing.T) {
	t.Log(socks.ParseAddr("127.0.0.1:1080"))
	t.Log(socks5client.ParseAddr("127.0.0.1:1080"))
}
