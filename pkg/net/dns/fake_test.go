package dns

import (
	"errors"
	"math/big"
	"net"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

/*
func TestFake(t *testing.T) {
	_, z, err := net.ParseCIDR("ff::ff/24")
	assert.NoError(t, err)

	ones, bites := z.Mask.Size()
	t.Log(math.Pow(2, float64(bites-ones)) - 1)

	f := NewFake(z)

	ip := f.GetFakeIPForDomain("a.com")
	t.Log(ip)
	t.Log(f.GetDomainFromIP(ip))
	ip = f.GetFakeIPForDomain("b.com")
	t.Log(ip)
	t.Log(f.GetDomainFromIP(ip))
	ip = f.GetFakeIPForDomain("c.com")
	t.Log(ip)
	t.Log(f.GetDomainFromIP(ip))
	ip = f.GetFakeIPForDomain("d.com")
	t.Log(ip)
	t.Log(f.GetDomainFromIP(ip))
	ip = f.GetFakeIPForDomain("e.com")
	t.Log(ip)
	t.Log(f.GetDomainFromIP(ip))
	ip = f.GetFakeIPForDomain("f.com")
	t.Log(ip)
	t.Log(f.GetDomainFromIP(ip))

	t.Log(f.GetFakeIPForDomain("b.com"))
	t.Log(f.GetFakeIPForDomain("c.com"))
	t.Log(f.GetFakeIPForDomain("d.com"))
	t.Log(f.GetFakeIPForDomain("e.com"))
	t.Log(f.GetFakeIPForDomain("f.com"))
	t.Log(f.GetFakeIPForDomain("g.com"))
	t.Log(f.GetFakeIPForDomain("h.com"))
	t.Log(f.GetFakeIPForDomain("i.com"))
	t.Log(f.GetFakeIPForDomain("j.com"))
}
*/

func TestPtr(t *testing.T) {
	zz, err := netip.ParsePrefix("1.1.1.1/12")
	assert.NoError(t, err)

	f := NewFakeIPPool(zz, nil)
	t.Log(f.GetFakeIPForDomain("aass"))

	z := &FakeDNS{
		DNS:        dns.ErrorDNS(func(domain string) error { return errors.New("err") }),
		FakeIPPool: NewFakeIPPool(zz, nil),
	}

	z.LookupPtr("f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.0.0.ip6.arpa.")
	z.LookupPtr("f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.ip6.arpa.")
	z.LookupPtr("1.0.0.127.in-addr.arpa.")
	z.LookupPtr("1.2.0.10.in-addr.arpa.")
}

func TestRetrieveIPFromPtr(t *testing.T) {
	t.Log(RetrieveIPFromPtr("f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.0.0.ip6.arpa."))
	t.Log(RetrieveIPFromPtr("1.2.0.10.in-addr.arpa."))
	t.Log(RetrieveIPFromPtr("4.9.0.0.a.1.8.6.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.0.7.4.6.0.6.2.ip6.arpa."))
}

func TestFakeGenerate(t *testing.T) {
	_, z, err := net.ParseCIDR("ff::ff/24")
	assert.NoError(t, err)

	t.Log([]byte(z.IP.To16()))

	i := big.NewInt(0).SetBytes(z.IP)

	t.Log(i, i.Bytes())

	i = i.Add(i, big.NewInt(70000))

	t.Log(append([]byte{0}, i.Bytes()...), net.IP(append([]byte{0}, i.Bytes()...)))
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
