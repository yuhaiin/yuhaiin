package netapi

import (
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

func TestKey(t *testing.T) {
	domain, err := ParseDomainPort("tcp", "www.google.com", 443)
	assert.NoError(t, err)
	ip := ParseIPAddr("tcp", net.ParseIP("127.0.0.1"), 443)

	var x syncmap.SyncMap[uint64, Address]
	x.Store(domain.Comparable(), domain)
	x.Store(ip.Comparable(), ip)

	re, ok := x.Load(domain.Comparable())
	assert.Equal(t, true, ok)
	assert.Equal(t, true, domain.Comparable() == re.Comparable())

	ri, ok := x.Load(ip.Comparable())
	assert.Equal(t, true, ok)
	assert.Equal(t, true, ip.Comparable() == ri.Comparable())

	z1 := domain.Comparable()
	newDomain, err := ParseDomainPort("tcp", "www.google.com", 443)
	assert.NoError(t, err)
	z2 := newDomain.Comparable()
	z3 := ip.Comparable()

	assert.Equal(t, z1, z2)
	assert.Equal(t, domain, newDomain)
	assert.Equal(t, false, z1 == z3)

	t.Log(z1, z2, z3)
}

func TestSysAddrComparableMatchesParseSysAddr(t *testing.T) {
	for _, addr := range []net.Addr{
		&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 53},
		&net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 443, Zone: "eth0"},
		&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80},
		DomainAddr{HostnameX: "example.com", PortX: 443, AddressNetwork: UDP},
	} {
		parsed, err := ParseSysAddr(addr)
		assert.NoError(t, err)
		got, err := SysAddrComparable(addr)
		assert.NoError(t, err)
		assert.Equal(t, parsed.Comparable(), got)
	}
	u := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 53}
	assert.Equal(t, float64(0), testing.AllocsPerRun(100, func() { _, _ = SysAddrComparable(u) }))
}
