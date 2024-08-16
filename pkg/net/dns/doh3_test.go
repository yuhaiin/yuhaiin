package dns

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDoh3(t *testing.T) {
	dialer.Bootstrap = &dialer.SystemResolver{}

	configMap := map[string]Config{
		"cloudflare": {
			Type: dns.Type_doh3,
			Host: "cloudflare-dns.com",
		},
		"ali": {
			Type: dns.Type_doh3,
			Host: "223.5.5.5",
		},
		"1.12.12.12": {
			Type: dns.Type_doh3,
			Host: "1.12.12.12",
		},
	}

	c, err := New(configMap["cloudflare"])
	assert.NoError(t, err)

	t.Log(c.LookupIP(context.TODO(), "www.google.com"))
	t.Log(c.LookupIP(context.TODO(), "www.baidu.com"))
	t.Log(c.LookupIP(context.TODO(), "www.qq.com"))
}
