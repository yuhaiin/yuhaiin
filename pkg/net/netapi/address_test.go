package netapi

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func TestKey(t *testing.T) {
	domain := ParseDomainPort("tcp", "www.google.com", 443)
	ip := ParseIPAddr("tcp", net.ParseIP("127.0.0.1"), 443)

	var x syncmap.SyncMap[ComparableAddress, Address]
	x.Store(domain.Comparable(), domain)
	x.Store(ip.Comparable(), ip)

	re, ok := x.Load(domain.Comparable())
	assert.Equal(t, true, ok)
	assert.Equal(t, true, domain.Comparable() == re.Comparable())

	ri, ok := x.Load(ip.Comparable())
	assert.Equal(t, true, ok)
	assert.Equal(t, true, ip.Comparable() == ri.Comparable())

	z1 := domain.Comparable()
	newDomain := ParseDomainPort("tcp", "www.google.com", 443)
	z2 := newDomain.Comparable()
	z3 := ip.Comparable()

	assert.Equal(t, z1, z2)
	assert.Equal(t, domain, newDomain)
	assert.Equal(t, false, z1 == z3)
	assert.Equal(t, ComparableAddress{}, ComparableAddress{})
}
