package socks5server

import (
	"net"
	"testing"

	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

func TestResolveAddr(t *testing.T) {
	x, err := s5c.ParseAddr("www.baidu.com:443")
	if err != nil {
		t.Error(err)
	}
	t.Log(s5c.ResolveAddr(x))
	x, err = s5c.ParseAddr("127.0.0.1:443")
	if err != nil {
		t.Error(err)
	}
	t.Log(x[0], x[1], x[2], x[3], x[4], x[3:], x[:3], x[:])
	t.Log(s5c.ResolveAddr(x))
	x, err = s5c.ParseAddr("ff::ff:443")
	if err != nil {
		t.Error(err)
	}
	t.Log(s5c.ResolveAddr(x))

	addr, err := net.ResolveIPAddr("ip", "www.baidu.com")
	if err != nil {
		t.Error(err)
	}
	t.Log(addr.IP)
}
