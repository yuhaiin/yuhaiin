package dns

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
)

func TestDoh3(t *testing.T) {
	c := NewDoH3(dns.Config{Host: "cloudflare-dns.com"}, nil)

	t.Log(c.LookupIP("www.google.com"))
	t.Log(c.LookupIP("www.baidu.com"))
	t.Log(c.LookupIP("www.qq.com"))
}
