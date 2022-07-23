package dns

import (
	"net"
	"testing"

	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestDOH(t *testing.T) {
	_, s, _ := net.ParseCIDR("223.5.5.5/24")
	_ = s
	// d := NewDoH("cloudflare-dns.com", nil)
	// d := NewDoH("public.dns.iij.jp", s, nil)
	d := New(Config{
		Type:   config.Dns_doh,
		Host:   "dns.google",
		IPv6:   true,
		Dialer: s5c.Dial("127.0.0.1", "1080", "", ""),
	})
	// d := NewDoH(dns.Config{Host: "9.9.9.9", Subnet: s, IPv6: true}, nil)
	// d := NewDoH(dns.Config{Host: "43.154.169.30", Servername: "a.passcloud.xyz"}, s5c.Dial("127.0.0.1", "1080", "", ""))
	// d := NewDoH("1.1.1.1", nil, nil)
	// d := NewDoH("1.0.0.1", nil, nil)
	// d := NewDoH(dns.Config{Host: "223.5.5.5", Subnet: s}, nil)
	// d := NewDoH(dns.Config{Host: "120.53.53.53", Subnet: s}, nil)
	// d := NewDoH("sm2.doh.pub", s, nil)
	// d := NewDoH("doh.pub", nil, nil)
	// d := NewDoH("101.6.6.6:8443", nil)
	// d := NewDoH("doh.360.cn", s, nil)
	// d := NewDOH("doh.dns.sb")
	// d := NewDoH("doh.opendns.com", nil)
	// _, s, _ := net.ParseCIDR("45.32.51.197/31")
	//t.Log(d.LookupIP("plasma"))
	t.Log(d.LookupIP("dc.services.visualstudio.com")) // -> will error, but not found reason
	t.Log(d.LookupIP("i2.hdslb.com"))
	t.Log(d.LookupIP("www.baidu.com"))
	t.Log(d.LookupIP("push.services.mozilla.com"))
	t.Log(d.LookupIP("www.google.com"))
	t.Log(d.LookupIP("www.pixiv.net"))
	t.Log(d.LookupIP("s1.hdslb.com"))
	t.Log(d.LookupIP("dns.nextdns.io"))
	t.Log(d.LookupIP("bilibili.com"))
	t.Log(d.LookupIP("test-ipv6.com"))
	//t.Log(d.LookupIP("baidu.com"))
	//t.Log(d.LookupIP("ss1.bdstatic.com"))
	//t.Log(d.LookupIP("dns.nextdns.io"))
	//t.Log(DOH("dns.google", "www.twitter.com"))
	// t.Log(DOH("cloudflare-dns.com", "www.twitter.com"))
	// t.Log(DOH("dns.google", "www.facebook.com"))
	// t.Log(DOH("cloudflare-dns.com", "www.facebook.com"))
	// t.Log(DOH("dns.google", "www.v2ex.com"))
	// t.Log(DOH("cloudflare-dns.com", "www.v2ex.com"))
	// t.Log(DOH("dns.google", "www.baidu.com"))
	// t.Log(DOH("cloudflare-dns.com", "www.baidu.com"))
	//t.Log(DOH("dns.google", "www.google.com"))
	//t.Log(DOH("cloudflare-dns.com", "www.google.com"))
	//t.Log(DOH("cloudflare-dns.com", "www.google.com"))
	//t.Log(DOH("cloudflare-dns.com", "www.google.com"))
	//t.Log(DOH("cloudflare-dns.com", "www.google.com"))
	//t.Log(DOH("dns.google", "www.archlinux.org"))
	//t.Log(DOH("dns.google", "yahoo.co.jp"))

	//t.Log(DOH("cloudflare-dns.com", "test-ipv6.nextdns.io"))
	//t.Log(DOH("dns.nextdns.io", "google.com"))

	// t.Log(DOH("cloudflare-dns.com", "115-235-111-150.dhost.00cdn.com"))
}

func TestGetURL(t *testing.T) {
	dnsQStr := "https://8.8.8.8/dns-query"
	assert.Equal(t, getUrlAndHost("https://8.8.8.8"), dnsQStr)
	assert.Equal(t, getUrlAndHost("8.8.8.8"), dnsQStr)

	t.Log(getUrlAndHost("https://"))
	t.Log(getUrlAndHost("/dns-query"))
}
