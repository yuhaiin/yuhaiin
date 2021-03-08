package dns

import "testing"

func TestDOT(t *testing.T) {
	d := NewDOT("223.5.5.5:853")
	t.Log(d.Search("www.google.com"))
	t.Log(d.Search("www.baidu.com"))
	d.SetServer("dns.pub:853")
	t.Log(d.Search("www.google.com"))
	t.Log(d.Search("www.baidu.com"))
	d.SetServer("dot.360.cn:853")
	t.Log(d.Search("www.google.com"))
	t.Log(d.Search("www.baidu.com"))
}
