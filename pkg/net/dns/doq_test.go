package dns

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func TestDoQ(t *testing.T) {
	// d := NewDoQ("dns.adguard.com:8853", nil, s5c.Dial("127.0.0.1", "1080", "", ""))
	// d := NewDoQ("dns-family.adguard.com:8853", "", nil, nil)
	d := New(Config{
		Type:       config.Dns_doq,
		Host:       "43.154.169.30",
		Servername: "a.passcloud.xyz", IPv6: true})
	t.Log(d.LookupIP("www.google.com"))
	t.Log(d.LookupIP("www.baidu.com"))
}
