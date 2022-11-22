package dns

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
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

	dns, err := New(configMap["114"])
	assert.NoError(t, err)

	t.Log(dns.LookupIP("baidu.com"))
	t.Log(dns.LookupIP("google.com"))
}
