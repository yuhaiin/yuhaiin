package resolver

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestTCP(t *testing.T) {
	subnet, _ := netip.ParsePrefix("1.1.1.1/32")

	configMap := map[string]Config{
		"114": {
			Type:   config.Type_tcp,
			Host:   "114.114.114.114",
			Subnet: subnet,
		},
		"ali": {
			Type:   config.Type_tcp,
			Host:   "223.5.5.5",
			Subnet: subnet,
		},
	}

	dns, err := New(configMap["114"])
	assert.NoError(t, err)

	t.Log(dns.LookupIP(context.TODO(), "www.baidu.com"))
	t.Log(dns.LookupIP(context.TODO(), "www.google.com"))
}
