package statistic

import (
	"bytes"
	"net"
	"testing"

	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

func TestMode(t *testing.T) {
	v := (any)(nil)

	v, ok := v.(MODE)
	if !ok {
		t.Log("!OK", v)
	} else {
		t.Log("OK", v)
	}
}

func TestDiffDNS(t *testing.T) {
	z := !proto.Equal(&protoconfig.Dns{}, &protoconfig.Dns{})
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
	str := "#abcdefg"
	i := bytes.IndexByte([]byte(str), '#')
	if i != -1 {
		t.Log(str[:i])
	}

	str = "abcdefg adada cccc#ddsd"
	i = bytes.IndexByte([]byte(str), '#')
	if i != -1 {
		t.Log(str[:i])
	}

	str = "aaaaabbbbbb "
	a := []byte(str)
	i = bytes.IndexByte(a, ' ')
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
