package maxminddb

import (
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestLookup(t *testing.T) {
	db, err := NewMaxMindDB("Country-without-asn.mmdb")
	assert.NoError(t, err)

	country, err := db.Lookup(netip.AddrFrom4([4]byte{1, 1, 1, 1}))
	assert.NoError(t, err)
	t.Log(country)
}
