package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDOH(t *testing.T) {
	netapi.Bootstrap = &netapi.SystemResolver{DisableIPv6: true}
	s, err := netip.ParsePrefix("223.5.5.5/24")
	assert.NoError(t, err)
	s5Dialer := socks5.Dial("127.0.0.1", "1080", "", "")

	configMap := map[string]Config{
		"google": {
			Type:   dns.Type_doh,
			Host:   "dns.google",
			IPv6:   true,
			Subnet: s,
			Dialer: s5Dialer,
		},
		"iijJP": {
			Type:       dns.Type_doh,
			Host:       "103.2.57.5",
			Servername: "public.dns.iij.jp",
			IPv6:       true,
			Subnet:     s,
		},
		"cloudflare": {
			Type:   dns.Type_doh,
			Host:   "cloudflare-dns.com",
			Subnet: s,
			IPv6:   true,
			Dialer: s5Dialer,
		},
		"quad9": {
			Type:   dns.Type_doh,
			Host:   "9.9.9.9",
			Subnet: s,
			IPv6:   true,
		},
		"a.passcloud": {
			Type:   dns.Type_doh,
			Host:   "a.passcloud.xyz",
			Subnet: s,
			IPv6:   true,
		},
		"adguard": {
			Type: dns.Type_doh,
			Host: "https://unfiltered.adguard-dns.com/dns-query",
			IPv6: true,
		},
		"ali": {
			Type:   dns.Type_doh,
			Host:   "223.5.5.5",
			Subnet: s,
		},
		"dns.pub": {
			Type:   dns.Type_doh,
			Host:   "dns.pub",
			Subnet: s,
			IPv6:   true,
		},
		"sm2.dnspub": {
			Type:   dns.Type_doh,
			Host:   "sm2.doh.pub",
			Subnet: s,
			IPv6:   true,
		},
		"360": {
			Type:   dns.Type_doh,
			Host:   "doh.360.cn",
			Subnet: s,
			IPv6:   true,
		},
		"dnssb": {
			Type:   dns.Type_doh,
			Host:   "doh.dns.sb",
			Subnet: s,
			IPv6:   true,
			Dialer: s5Dialer,
		},
		"opendns": {
			Type:   dns.Type_doh,
			Host:   "doh.opendns.com",
			Subnet: s,
			IPv6:   true,
			Dialer: s5Dialer,
		},
		"tuna": {
			Type: dns.Type_doh,
			Host: "https://101.6.6.6:8443/dns-query",
		},
	}

	d, err := New(configMap["dns.pub"])
	assert.NoError(t, err)

	t.Log(d.LookupIP(context.TODO(), "plasma"))
	t.Log(d.LookupIP(context.TODO(), "fonts.gstatic.com"))
	// t.Log(d.LookupIP(context.TODO(), "dc.services.visualstudio.com")) // -> will error, but not found reason
	t.Log(d.LookupIP(context.TODO(), "i2.hdslb.com"))
	t.Log(d.LookupIP(context.TODO(), "www.baidu.com"))
	// t.Log(d.LookupIP(context.TODO(), "push.services.mozilla.com"))
	// t.Log(d.LookupIP(context.TODO(), "www.google.com"))
	// t.Log(d.LookupIP(context.TODO(), "www.pixiv.net"))
	// t.Log(d.LookupIP(context.TODO(), "s1.hdslb.com"))
	// t.Log(d.LookupIP(context.TODO(), "dns.nextdns.io"))
	// t.Log(d.LookupIP(context.TODO(), "bilibili.com"))
	// t.Log(d.LookupIP(context.TODO(), "test-ipv6.com"))
	// t.Log(d.LookupIP(context.TODO(), "ss1.bdstatic.com"))
	// t.Log(d.LookupIP(context.TODO(), "www.twitter.com"))
	// t.Log(d.LookupIP(context.TODO(), "www.facebook.com"))
	// t.Log(d.LookupIP(context.TODO(), "yahoo.co.jp"))
	// t.Log(d.LookupIP(context.TODO(), "115-235-111-150.dhost.00cdn.com"))

	t.Log(d.Raw(context.TODO(), dnsmessage.Question{
		Name: dnsmessage.MustNewName("www.google.com."),
		Type: dnsmessage.TypeA,
	}))
	t.Log(d.Raw(context.TODO(), dnsmessage.Question{
		Name: dnsmessage.MustNewName("www.google.com."),
		Type: dnsmessage.TypeA,
	}))
}

func TestGetURL(t *testing.T) {
	dnsQStr := "https://8.8.8.8/dns-query"
	assert.Equal(t, getUrlAndHost("https://8.8.8.8"), dnsQStr)
	assert.Equal(t, getUrlAndHost("8.8.8.8"), dnsQStr)

	t.Log(getUrlAndHost("https://"))
	t.Log(getUrlAndHost("/dns-query"))
}
