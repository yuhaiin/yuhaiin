package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestV(t *testing.T) {
	t.Log(netip.AddrFrom16(netip.AddrFrom4([4]byte{192, 168, 2, 245}).As16()))
}

func TestDoQ(t *testing.T) {
	netapi.Bootstrap = &netapi.System{DisableIPv6: true}

	s5Dialer := s5c.Dial("127.0.0.1", "1080", "", "")

	configMap := map[string]Config{
		"adguard": {
			Type:   dns.Type_doq,
			Host:   "dns.adguard.com:8853",
			Dialer: s5Dialer,
			IPv6:   true,
		},
		"a.passcoud": {
			Type: dns.Type_doq,
			Host: "a.passcloud.xyz",
			IPv6: true,
		},
		"c.passcloud": {
			Type: dns.Type_doq,
			Host: "c.passcoud.xyz:784",
			IPv6: true,
		},
		"nextdns": {
			Type:   dns.Type_doq,
			Host:   "dns.nextdns.io:853",
			IPv6:   true,
			Dialer: s5Dialer,
		},
	}

	d, err := New(configMap["nextdns"])
	assert.NoError(t, err)

	defer d.Close()

	t.Log(d.LookupIP(context.TODO(), "www.google.com"))
	t.Log(d.LookupIP(context.TODO(), "www.baidu.com"))
}
