package dns

import (
	"testing"

	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func TestDoQ(t *testing.T) {
	d := New(
		Config{
			Type:   config.Dns_doq,
			Host:   "dns.adguard.com:8853",
			Dialer: s5c.Dial("127.0.0.1", "1080", "", ""),
			IPv6:   true,
		})
	// defer d.Close()
	// d := NewDoQ("dns-family.adguard.com:8853", "", nil, nil)

	// d := New(Config{
	// 	Dialer:     s5c.Dial("127.0.0.1", "1080", "", ""),
	// 	Type:       config.Dns_doq,
	// 	Host:       "43.154.169.30",
	// 	Servername: "a.passcloud.xyz",
	// 	IPv6:       true,
	// })
	// d := New(Config{
	// 	Dialer: s5c.Dial("127.0.0.1", "1080", "", ""),
	// 	Type:   config.Dns_doq,
	// 	// Host:       "43.154.169.30",
	// 	Host: "a.passcloud.xyz",
	// 	IPv6: true,
	// })
	t.Log(d.LookupIP("www.google.com"))
	t.Log(d.LookupIP("www.baidu.com"))
}
