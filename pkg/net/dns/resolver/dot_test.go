package resolver

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDOT(t *testing.T) {
	s, _ := netip.ParsePrefix("223.5.5.5/22")
	configMap := map[string]Config{
		"google": {
			Type:   config.Type_dot,
			Host:   "8.8.8.8",
			Subnet: s,
			Dialer: socks5.Dial("127.0.0.1", "1080", "", ""),
		},
		"ali": {
			Type:   config.Type_dot,
			Host:   "223.5.5.5",
			Subnet: s,
		},
		"dnspub": {
			Type:   config.Type_dot,
			Host:   "dot.pub:853",
			Subnet: s,
		},
		"360": {
			Type:   config.Type_dot,
			Host:   "dot.360.cn:853",
			Subnet: s,
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
