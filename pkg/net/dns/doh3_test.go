package dns

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDoh3(t *testing.T) {
	netapi.Bootstrap = &netapi.SystemResolver{}

	configMap := map[string]Config{
		"cloudflare": {
			Type: dns.Type_doh3,
			Host: "cloudflare-dns.com",
		},
	}

	c, err := New(configMap["cloudflare"])
	assert.NoError(t, err)

	t.Log(c.LookupIP(context.TODO(), "www.google.com"))
	t.Log(c.LookupIP(context.TODO(), "www.baidu.com"))
	t.Log(c.LookupIP(context.TODO(), "www.qq.com"))
}
