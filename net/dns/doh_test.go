package dns

import (
	"testing"
)

func TestDOH(t *testing.T) {
	t.Log(DOH("dns.google", "www.twitter.com"))
	t.Log(DOH("cloudflare-dns.com", "www.twitter.com"))
	t.Log(DOH("dns.google", "www.facebook.com"))
	t.Log(DOH("cloudflare-dns.com", "www.facebook.com"))
	t.Log(DOH("dns.google", "www.v2ex.com"))
	t.Log(DOH("cloudflare-dns.com", "www.v2ex.com"))
	t.Log(DOH("dns.google", "www.baidu.com"))
	t.Log(DOH("cloudflare-dns.com", "www.baidu.com"))
	t.Log(DOH("dns.google", "www.google.com"))
	t.Log(DOH("cloudflare-dns.com", "www.google.com"))
}
