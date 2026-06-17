package maxminddb

import (
	"net/netip"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestLookup(t *testing.T) {
	if _, err := os.Stat("Country-without-asn.mmdb"); err != nil {
		t.Skip("requires Country-without-asn.mmdb test fixture")
	}

	db, err := NewMaxMindDB("Country-without-asn.mmdb")
	assert.NoError(t, err)

	country, err := db.Lookup(netip.AddrFrom4([4]byte{1, 1, 1, 1}))
	assert.NoError(t, err)
	t.Log(country)
}
