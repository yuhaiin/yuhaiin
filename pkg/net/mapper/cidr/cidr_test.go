package cidr

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestCidrMatch(t *testing.T) {
	cidrMatch := NewCidrMapper[string]()
	assert.NoError(t, cidrMatch.Insert("10.2.2.1/18", "testIPv4"))
	assert.NoError(t, cidrMatch.Insert("2001:0db8:0000:0000:1234:0000:0000:9abc/32", "testIPv6"))
	assert.NoError(t, cidrMatch.Insert("127.0.0.1/8", "testlocal"))
	assert.NoError(t, cidrMatch.Insert("ff::/16", "testV6local"))

	search := func(s string) string {
		res, _ := cidrMatch.Search(s)
		return res
	}

	testIPv4 := "10.2.2.1"
	testIPv4b := "100.2.2.1"
	testIPv6 := "2001:0db8:0000:0000:1234:0000:0000:9abc"
	testIPv6b := "3001:0db8:0000:0000:1234:0000:0000:9abc"

	assert.Equal(t, "testIPv4", search(testIPv4))
	assert.Equal(t, "testIPv6", search(testIPv6))
	assert.Equal(t, "testlocal", search("127.1.1.1"))
	assert.Equal(t, "", search("129.1.1.1"))
	assert.Equal(t, "testV6local", search("ff:ff::"))
	assert.Equal(t, "", search(testIPv4b))
	assert.Equal(t, "", search(testIPv6b))
}

// BenchmarkCidrMatch_Search-4 40390761	 25.77 ns/op  16 B/op  1 allocs/op
func BenchmarkCidrMatch_Search(b *testing.B) {
	cidrMatch := NewCidrMapper[string]()
	assert.NoError(b, cidrMatch.Insert("10.2.2.1/18", "testIPv4"))
	assert.NoError(b, cidrMatch.Insert("2001:0db8:0000:0000:1234:0000:0000:9abc/32", "testIPv6"))

	testIPv4 := "10.2.2.1"
	//testIPv4b := "100.2.2.1"
	//testIPv6 := "2001:0db8:0000:0000:1234:0000:0000:9abc"
	// testIPv6b := "3001:0db8:0000:0000:1234:0000:0000:9abc"

	b.RunParallel(func(p *testing.PB) {
		for p.Next() {
			cidrMatch.Search(testIPv4)
			// cidrMatch.Search(testIPv6b)
		}
	})
}
