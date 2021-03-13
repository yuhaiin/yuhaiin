package dns

import (
	"net"
	"testing"
)

func TestDOH(t *testing.T) {
	// d := NewDOH("cloudflare-dns.com")
	// d := NewDOH("public.dns.iij.jp")
	// d := NewDOH("dns.google")
	// d := NewDOH("dns.nextdns.io/e28bb3", nil)
	// d := NewDOH("1.1.1.1")
	// d := NewDOH("1.0.0.1")
	//d := NewDOH("223.5.5.5")
	// d := NewDOH("doh.pub")
	d := NewDOH("101.6.6.6:8443", nil)
	//d := NewDOH("doh.360.cn")
	// d := NewDOH("doh.dns.sb")
	// d := NewDOH("doh.opendns.com")
	// _, s, _ := net.ParseCIDR("45.32.51.197/31")

	_, s, _ := net.ParseCIDR("114.114.114.114/31")
	d.SetSubnet(s)
	//t.Log(d.Search("plasma"))
	t.Log(d.Search("dc.services.visualstudio.com")) // -> will error, but not found reason
	t.Log(d.Search("i2.hdslb.com"))
	t.Log(d.Search("www.baidu.com"))
	//t.Log(d.Search("baidu.com"))
	//t.Log(d.Search("ss1.bdstatic.com"))
	//t.Log(d.Search("dns.nextdns.io"))
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
