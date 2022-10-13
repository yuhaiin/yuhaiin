package dns

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func TestDOT(t *testing.T) {
	// d := NewDoT("223.5.5.5", nil, nil)
	_, s, _ := net.ParseCIDR("223.5.5.5/22")
	// d := NewDoT("8.8.8.8", s, s5c.Dial("127.0.0.1", "1080", "", ""))
	d := New(Config{Type: dns.Type_dot, Host: "223.5.5.5", Subnet: s, IPv6: true})
	t.Log(d.LookupIP("i2.hdslb.com"))
	t.Log(d.LookupIP("www.google.com"))
	t.Log(d.LookupIP("www.baidu.com"))
	t.Log(d.LookupIP("www.apple.com"))
	t.Log(d.LookupIP("www.example.com"))
	// d.SetServer("dot.pub:853") //  not support ENDS, so shit
	// t.Log(d.LookupIP("www.google.com"))
	// t.Log(d.LookupIP("www.baidu.com"))
	// d.SetServer("dot.360.cn:853")
	// t.Log(d.LookupIP("www.google.com"))
	// t.Log(d.LookupIP("www.baidu.com"))
}
