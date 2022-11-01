package dns

import (
	"net"
	"testing"

	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func TestDOT(t *testing.T) {
	_, s, _ := net.ParseCIDR("223.5.5.5/22")
	configMap := map[string]Config{
		"google": {
			Type:   dns.Type_dot,
			Host:   "8.8.8.8",
			Subnet: s,
			IPv6:   true,
			Dialer: s5c.Dial("127.0.0.1", "1080", "", ""),
		},
		"ali": {
			Type:   dns.Type_dot,
			Host:   "223.5.5.5",
			Subnet: s,
			IPv6:   true,
		},
		"dnspub": {
			Type:   dns.Type_dot,
			Host:   "dot.pub:853",
			Subnet: s,
			IPv6:   true,
		},
		"360": {
			Type:   dns.Type_dot,
			Host:   "dot.360.cn:853",
			Subnet: s,
			IPv6:   true,
		},
	}

	d := New(configMap["google"])
	t.Log(d.LookupIP("i2.hdslb.com"))
	t.Log(d.LookupIP("www.google.com"))
	t.Log(d.LookupIP("www.baidu.com"))
	t.Log(d.LookupIP("www.apple.com"))
	t.Log(d.LookupIP("www.example.com"))
}
