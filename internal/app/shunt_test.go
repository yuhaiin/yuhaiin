package app

import (
	"bytes"
	"math/bits"
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

func TestIndex(t *testing.T) {
	str := "aaaaabbbbbb "
	a := []byte(str)
	i := bytes.IndexByte(a, ' ')
	if i == -1 {
		return
	}
	c := a[:i]
	i2 := bytes.IndexByte(a[i+1:], ' ')
	var b []byte
	if i2 != -1 {
		b = a[i+1 : i2+i+1]
	} else {
		b = a[i+1:]
	}

	if bytes.Equal(b, []byte{}) {
		t.Log("empty")
	}

	t.Log(i, i2+i+1)
	t.Log(string(c), string(b)+";")
}

func TestM(t *testing.T) {
	z := make([]byte, 17)

	for i := range z {
		t.Log(bits.Len32(uint32(i)))
		t.Log(1 << i)
	}
}

func TestGetDNSHostnameAndMode(t *testing.T) {
	s, m := getDNSHostnameAndMode(&config.DNS{Host: "1.1.1.1"})
	t.Log(s, m)
}
