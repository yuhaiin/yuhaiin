package dns

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func TestTCP(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("1.1.1.1/32")

	configMap := map[string]Config{
		"114": {
			Type:   dns.Type_tcp,
			Host:   "114.114.114.114",
			Subnet: subnet,
			IPv6:   true,
		},
	}

	dns := New(configMap["114"])
	t.Log(dns.LookupIP("baidu.com"))
	t.Log(dns.LookupIP("google.com"))
}
