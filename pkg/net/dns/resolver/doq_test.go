package resolver

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDoQ(t *testing.T) {
	t.Skip("requires external DoQ services")

	s5Dialer := socks5.Dial("127.0.0.1", "1080", "", "")

	configMap := map[string]Config{
		"adguard": {
			Type:   "doq",
			Host:   "dns.adguard.com:8853",
			Dialer: s5Dialer,
		},
		"a.passcoud": {
			Type: "doq",
			Host: "a.passcloud.xyz",
		},
		"c.passcloud": {
			Type: "doq",
			Host: "c.passcoud.xyz:784",
		},
		"nextdns": {
			Type:   "doq",
			Host:   "dns.nextdns.io:853",
			Dialer: s5Dialer,
		},
		"controld": {
			Type: "doq",
			Host: "p0.freedns.controld.com:853",
		},
	}

	d, err := New(configMap["controld"])
	assert.NoError(t, err)

	defer d.Close()

	t.Log(d.LookupIP(context.TODO(), "www.google.com"))
	t.Log(d.LookupIP(context.TODO(), "www.baidu.com"))
}
