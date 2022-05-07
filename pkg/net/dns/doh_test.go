package dns

import (
	"context"
	"net"
	"testing"
)

func TestDOH(t *testing.T) {
	// _, s, _ := net.ParseCIDR("223.5.5.5/22")
	// d := NewDoH("cloudflare-dns.com", nil)
	// d := NewDoH("public.dns.iij.jp", s, nil)
	// d := NewDoH("dns.google", s, s5c.Dial("127.0.0.1", "1080", "", ""))
	// d := NewDoH("dns.nextdns.io/e28bb3", nil)
	// d := NewDoH("1.1.1.1", nil)
	// d := NewDoH("1.0.0.1", nil)
	// d := NewDoH("223.5.5.5", s, nil)
	// d := NewDoH("sm2.doh.pub", s, nil)
	d := NewDoH("doh.pub", nil, nil)
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
	t.Log(d.Resolver().LookupIP(context.Background(), "ip", "s1.hdslb.com"))
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

func TestSplit(t *testing.T) {
	t.Log(net.SplitHostPort("www.google.com"))
	t.Log(net.SplitHostPort("www.google.com:443"))
}

func TestResolver(t *testing.T) {
	_, s, _ := net.ParseCIDR("114.114.114.114/31")
	d := NewDoH("223.5.5.5", s, nil)
	// d := NewDoH("1.1.1.1", s, nil)

	t.Log(d.(*doh).Resolver().LookupHost(context.Background(), "www.baidu.com"))
	t.Log(d.(*doh).Resolver().LookupHost(context.Background(), "www.google.com"))
	t.Log(d.(*doh).Resolver().LookupHost(context.Background(), "www.cloudflare.com"))
	t.Log(d.(*doh).Resolver().LookupHost(context.Background(), "www.apple.com"))
}
