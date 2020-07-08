package dns

import (
	"testing"
)

func TestDOH(t *testing.T) {
	//d := NewDOH("cloudflare-dns.com")
	//d := NewDOH("public.dns.iij.jp")
	//d := NewDOH("dns.google")
	d := NewDOH("dns.nextdns.io/e28bb3")
	//_, s, _ := net.ParseCIDR("45.32.51.197/31")
	//d.SetSubnet(s)
	t.Log(d.Search("i2.hdslb.com"))
	t.Log(d.Search("www.baidu.com"))
	t.Log(d.Search("baidu.com"))
	t.Log(d.Search("ss1.bdstatic.com"))
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
