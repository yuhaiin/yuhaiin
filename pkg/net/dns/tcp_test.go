package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestTCP(t *testing.T) {
	subnet, _ := netip.ParsePrefix("1.1.1.1/32")

	configMap := map[string]Config{
		"114": {
			Type:   dns.Type_tcp,
			Host:   "114.114.114.114",
			Subnet: subnet,
		},
	}

	dns, err := New(configMap["114"])
	assert.NoError(t, err)

	t.Log(dns.LookupIP(context.TODO(), "baidu.com"))
	t.Log(dns.LookupIP(context.TODO(), "google.com"))
}
