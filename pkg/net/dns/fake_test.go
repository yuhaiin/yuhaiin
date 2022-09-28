package dns

import (
	"fmt"
	"math"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestFake(t *testing.T) {
	_, z, err := net.ParseCIDR("127.0.0.1/24")
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

func TestPtr(t *testing.T) {
	_, zz, err := net.ParseCIDR("1.1.1.1/12")
	assert.NoError(t, err)

	f := NewFake(zz)
	t.Log(f.GetFakeIPForDomain("aass"))

	z := &FakeDNS{
		upStreamDo: dns.NewErrorDNS(fmt.Errorf("err")).Do,
		pool:       NewFake(zz),
	}

	z.LookupPtr("f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.0.0.ip6.arpa.")
	z.LookupPtr("f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f.f.ip6.arpa.")
	z.LookupPtr("1.0.0.127.in-addr.arpa.")
	z.LookupPtr("1.2.0.10.in-addr.arpa.")
}
