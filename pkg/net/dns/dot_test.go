package dns

import (
	"context"
	"net"
	"testing"
)

func TestDOT(t *testing.T) {
	// d := NewDoT("223.5.5.5", nil, nil)
	_, s, _ := net.ParseCIDR("223.5.5.5/22")
	// d := NewDoT("8.8.8.8", s, s5c.Dial("127.0.0.1", "1080", "", ""))
	d := NewDoT("8.8.4.4", "", s, nil)
	t.Log(d.LookupIP("i2.hdslb.com"))
	t.Log(d.LookupIP("www.google.com"))
	t.Log(d.LookupIP("www.baidu.com"))
	t.Log(d.LookupIP("www.apple.com"))
	t.Log(d.LookupIP("kctr.made1nheaven.xyz"))
	// d.SetServer("dot.pub:853") //  not support ENDS, so shit
	// t.Log(d.LookupIP("www.google.com"))
	// t.Log(d.LookupIP("www.baidu.com"))
	// d.SetServer("dot.360.cn:853")
	// t.Log(d.LookupIP("www.google.com"))
	// t.Log(d.LookupIP("www.baidu.com"))
}

func TestDOTResolver(t *testing.T) {
	dd := NewDoT("223.5.5.5", "", nil, nil)

	d := dd.(*tcp)

	t.Log(d.Resolver().LookupHost(context.Background(), "www.baidu.com"))
	t.Log(d.Resolver().LookupHost(context.Background(), "www.google.com"))
	t.Log(d.Resolver().LookupHost(context.Background(), "www.apple.com"))
}
