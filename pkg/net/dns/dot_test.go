package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDOT(t *testing.T) {
	s, _ := netip.ParsePrefix("223.5.5.5/22")
	configMap := map[string]Config{
		"google": {
			Type:   dns.Type_dot,
			Host:   "8.8.8.8",
			Subnet: s,
			IPv6:   true,
			Dialer: socks5.Dial("127.0.0.1", "1080", "", ""),
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

	d, err := New(configMap["google"])
	assert.NoError(t, err)

	t.Log(d.LookupIP(context.TODO(), "i2.hdslb.com"))
	t.Log(d.LookupIP(context.TODO(), "www.google.com"))
	t.Log(d.LookupIP(context.TODO(), "www.baidu.com"))
	t.Log(d.LookupIP(context.TODO(), "www.apple.com"))
	t.Log(d.LookupIP(context.TODO(), "www.example.com"))
}
