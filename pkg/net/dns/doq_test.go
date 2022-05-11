package dns

import (
	"testing"

	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

func TestDoQ(t *testing.T) {
	d := NewDoQ("dns.adguard.com:8853", nil, s5c.Dial("127.0.0.1", "1080", "", ""))
	// d := NewDoQ("dns-family.adguard.com:8853", nil, nil)
	// d := NewDoQ("a.passcloud.xyz", nil, nil)
	t.Log(d.LookupIP("www.google.com"))
	t.Log(d.LookupIP("www.baidu.com"))
}
