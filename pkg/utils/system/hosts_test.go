package system

import (
	"net"
	"testing"
)

func TestIsDomain(t *testing.T) {
	t.Log(IsDomainName("www.google.com"))
	t.Log(IsDomainName("www.google.com."))
	t.Log(IsDomainName("f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.0.0.ip6.arpa."))
	t.Log(IsDomainName("1.2.0.10.in-addr.arpa."))
	t.Log(IsDomainName("[2001:b28:f23d:f001::"))
	t.Log(IsDomainName("2001:b28:f23d:f001::"))
	t.Log(IsDomainName("getmobileredirecthost"))
}

func TestHosts(t *testing.T) {
	t.Log(LookupStaticAddr(net.ParseIP("127.0.0.1")))
	t.Log(LookupStaticHost("localhost"))
}
