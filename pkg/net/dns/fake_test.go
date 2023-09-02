package dns

import (
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func TestRetrieveIPFromPtr(t *testing.T) {
	t.Log(RetrieveIPFromPtr("f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.0.0.ip6.arpa."))
	t.Log(RetrieveIPFromPtr("1.2.0.10.in-addr.arpa."))
	t.Log(RetrieveIPFromPtr("4.9.0.0.a.1.8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.0.7.4.6.0.6.2.ip6.arpa."))
}

func TestNetip(t *testing.T) {
	t.Log(len("f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.f.f"))
	t.Log(yerror.Ignore(netip.ParseAddr("2606:4700:20::681a:ffff")).As16())

	z, err := netip.ParsePrefix("127.0.0.1/30")
	assert.NoError(t, err)

	ff := NewFakeIPPool(z, nil)

	getAndRev := func(a string) {
		ip := ff.GetFakeIPForDomain(a)
		host, _ := ff.GetDomainFromIP(ip)

		t.Log(a, ip, host)
	}

	getAndRev("aa")
	getAndRev("bb")
	getAndRev("cc")
	getAndRev("dd")
	getAndRev("aa")
	getAndRev("ee")
	getAndRev("ff")
}
