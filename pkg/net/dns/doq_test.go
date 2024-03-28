package dns

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDoQ(t *testing.T) {
	netapi.Bootstrap = &netapi.SystemResolver{}

	s5Dialer := socks5.Dial("127.0.0.1", "1080", "", "")

	configMap := map[string]Config{
		"adguard": {
			Type:   dns.Type_doq,
			Host:   "dns.adguard.com:8853",
			Dialer: s5Dialer,
		},
		"a.passcoud": {
			Type: dns.Type_doq,
			Host: "a.passcloud.xyz",
		},
		"c.passcloud": {
			Type: dns.Type_doq,
			Host: "c.passcoud.xyz:784",
		},
		"nextdns": {
			Type:   dns.Type_doq,
			Host:   "dns.nextdns.io:853",
			Dialer: s5Dialer,
		},
	}

	d, err := New(configMap["nextdns"])
	assert.NoError(t, err)

	defer d.Close()

	t.Log(d.LookupIP(context.TODO(), "www.google.com"))
	t.Log(d.LookupIP(context.TODO(), "www.baidu.com"))
}
