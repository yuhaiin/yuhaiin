package dns

import (
	"net"
	"testing"

	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestUDP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("223.5.5.0/24")
	s5Dialer := s5c.Dial("127.0.0.1", "1080", "", "")
	configMap := map[string]Config{
		"cloudflare": {
			Type:   dns.Type_udp,
			Host:   "one.one.one.one",
			Subnet: subnet,
			IPv6:   true,
			Dialer: s5Dialer,
		},
		"google": {
			Type:   dns.Type_udp,
			Host:   "8.8.8.8",
			Subnet: subnet,
			IPv6:   true,
			Dialer: s5Dialer,
		},
		"114": {
			Type:   dns.Type_udp,
			Host:   "114.114.114.114",
			Subnet: subnet,
			IPv6:   true,
		},
	}

	dns, err := New(configMap["cloudflare"])
	assert.NoError(t, err)

	t.Log(dns.LookupIP("www.baidu.com"))
	t.Log(dns.LookupIP("www.google.com"))
	t.Log(dns.LookupIP("www.twitter.com"))
	t.Log(dns.LookupIP("i2.hdslb.com"))
}
