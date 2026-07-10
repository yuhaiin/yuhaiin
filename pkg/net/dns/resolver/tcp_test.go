package resolver

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestTCP(t *testing.T) {
	t.Skip("requires external DNS services")

	subnet, _ := netip.ParsePrefix("1.1.1.1/32")

	configMap := map[string]Config{
		"114": {
			Type:   "tcp",
			Host:   "114.114.114.114",
			Subnet: subnet,
		},
		"ali": {
			Type:   "tcp",
			Host:   "223.5.5.5",
			Subnet: subnet,
		},
	}

	dns, err := New(configMap["114"])
	assert.NoError(t, err)

	t.Log(dns.LookupIP(context.TODO(), "www.baidu.com"))
	t.Log(dns.LookupIP(context.TODO(), "www.google.com"))
}
