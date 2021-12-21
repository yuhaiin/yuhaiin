package app

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/internal/config"
)

func TestShunt(t *testing.T) {
	x, err := NewShunt(&config.Config{}, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(x.Get("sp0.baidu.com"))
	t.Log(x.Get("www.baidu.com"))
	t.Log(x.Get("www.google.com"))
}

func TestMode(t *testing.T) {
	v := (interface{})(nil)

	v, ok := v.(MODE)
	if !ok {
		t.Log("!OK", v)
	} else {
		t.Log("OK", v)
	}
}

func TestDiffDNS(t *testing.T) {
	z := diffDNS(&config.DNS{}, &config.DNS{})
	t.Log(z)

	_, x, _ := net.ParseCIDR("1.1.1.1/32")
	t.Log(len(x.IP))
	t.Log([]byte(x.Mask))

	_, xx, _ := net.ParseCIDR("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")
	t.Log(len(xx.IP))
	t.Log([]byte(xx.Mask))

	t.Log(len(net.ParseIP("1.1.1.1")))
}
