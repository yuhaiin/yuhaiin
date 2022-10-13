package dns

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func TestDoh3(t *testing.T) {
	c := New(Config{
		Type: dns.Type_doh3,
		Host: "cloudflare-dns.com",
		IPv6: true,
	})

	t.Log(c.LookupIP("www.google.com"))
	t.Log(c.LookupIP("www.baidu.com"))
	t.Log(c.LookupIP("www.qq.com"))
}
