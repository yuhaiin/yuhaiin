package resolver

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestUDP(t *testing.T) {
	t.Skip("requires external DNS services")

	subnet, _ := netip.ParsePrefix("223.5.5.0/24")
	s5Dialer := socks5.Dial("127.0.0.1", "1080", "", "")
	configMap := map[string]Config{
		"cloudflare": {
			Type:   "udp",
			Host:   "one.one.one.one",
			Subnet: subnet,
			Dialer: s5Dialer,
		},
		"google": {
			Type:   "udp",
			Host:   "8.8.8.8",
			Subnet: subnet,
			Dialer: s5Dialer,
		},
		"114": {
			Type:   "udp",
			Host:   "114.114.114.114",
			Subnet: subnet,
		},
		"nextdns": {
			Type:   "udp",
			Host:   "45.90.28.30",
			Subnet: subnet,
			Dialer: s5Dialer,
		},
		"opendns": {
			Type:   "udp",
			Host:   "208.67.222.222:5353",
			Subnet: subnet,
			Dialer: s5Dialer,
		},
	}

	dns, err := New(configMap["114"])
	assert.NoError(t, err)

	t.Log(dns.LookupIP(context.TODO(), "www.baidu.com"))
	t.Log(dns.LookupIP(context.TODO(), "www.google.com"))
	t.Log(dns.LookupIP(context.TODO(), "www.twitter.com"))
	t.Log(dns.LookupIP(context.TODO(), "i2.hdslb.com"))
}
