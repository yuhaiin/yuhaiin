package dns

import (
	"context"
	"testing"
)

func TestDOT(t *testing.T) {
	d := NewDoT("223.5.5.5", nil, nil)
	t.Log(d.LookupIP("www.google.com"))
	t.Log(d.LookupIP("www.baidu.com"))
	t.Log(d.LookupIP("www.apple.com"))
	// d.SetServer("dot.pub:853") //  not support ENDS, so shit
	// t.Log(d.LookupIP("www.google.com"))
	// t.Log(d.LookupIP("www.baidu.com"))
	// d.SetServer("dot.360.cn:853")
	// t.Log(d.LookupIP("www.google.com"))
	// t.Log(d.LookupIP("www.baidu.com"))
}

func TestDOTResolver(t *testing.T) {
	d := NewDoT("223.5.5.5", nil, nil)
	t.Log(d.Resolver().LookupHost(context.Background(), "www.baidu.com"))
	t.Log(d.Resolver().LookupHost(context.Background(), "www.google.com"))
	t.Log(d.Resolver().LookupHost(context.Background(), "www.apple.com"))
}
