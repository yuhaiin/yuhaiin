package system

import "testing"

func TestIsDomain(t *testing.T) {
	t.Log(IsDomainName("www.google.com"))
	t.Log(IsDomainName("www.google.com."))
	t.Log(IsDomainName("f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.0.0.ip6.arpa."))
	t.Log(IsDomainName("1.2.0.10.in-addr.arpa."))
	t.Log(IsDomainName("[2001:b28:f23d:f001::"))
}
