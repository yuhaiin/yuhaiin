package dns

import (
	"testing"
)

func TestDoh3(t *testing.T) {
	c := NewDoH3("cloudflare-dns.com", nil)

	t.Log(c.LookupIP("www.google.com"))
	t.Log(c.LookupIP("www.baidu.com"))
	t.Log(c.LookupIP("www.qq.com"))
}
