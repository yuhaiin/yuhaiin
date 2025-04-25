package resolver

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestHostsStore(t *testing.T) {
	testHosts := [][2]string{
		{"www.example.com", "127.0.0.1"},       // no port map
		{"www.example.com:443", "8.8.8.8:443"}, // port map to 8.8.8.8:443
		{"www.google.com", "8.8.8.9:123"},      // no port map, because original port is 0
		{"www.google.com:443", "8.8.8.8"},      // no port map , override 8.8.8.9, because target port is 0
		{"1.1.1.1", "1.1.1.2"},                 // no port map
		{"1.1.1.1:443", "1.1.1.3"},             // no port map, override 1.1.1.2, because target port is 0
	}

	store := newHostsStore()

	for _, v := range testHosts {
		addr, err := netapi.ParseAddress("", v[0])
		assert.NoError(t, err)

		taddr, err := netapi.ParseAddress("", v[1])
		assert.NoError(t, err)

		store.add(addr, taddr)
	}

	for k, v := range map[string]string{
		"www.example.com:345": "127.0.0.1:345",
		"www.example.com:443": "8.8.8.8:443",
		"www.google.com:345":  "8.8.8.8:345",
		"www.google.com:443":  "8.8.8.8:443",
		"1.1.1.1:345":         "1.1.1.3:345",
		"1.1.1.1:443":         "1.1.1.3:443",
	} {
		addr, err := netapi.ParseAddress("", k)
		assert.NoError(t, err)

		taddr, err := netapi.ParseAddress("", v)
		assert.NoError(t, err)

		a, ok := store.lookup(addr)
		assert.MustEqual(t, ok, true)

		assert.MustEqual(t, a.Comparable(), taddr.Comparable())
	}

	for k, v := range map[string][]string{
		"127.0.0.1": {"www.example.com"},
		"1.1.1.3":   {},
		"8.8.8.8":   {"www.google.com"},
	} {
		addr, err := netip.ParseAddr(k)
		assert.NoError(t, err)

		ptrs := store.lookupPtr(addr)

		assert.MustEqual(t, true, slices.Equal(ptrs, v))
	}
}
