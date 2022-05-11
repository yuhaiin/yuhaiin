package mapper

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCidrMatch_Inset(t *testing.T) {
	cidrMatch := NewCidrMapper[string]()
	require.Nil(t, cidrMatch.Insert("10.2.2.1/18", "testIPv4"))
	require.Nil(t, cidrMatch.Insert("2001:0db8:0000:0000:1234:0000:0000:9abc/32", "testIPv6"))
	require.Nil(t, cidrMatch.Insert("127.0.0.1/8", "testlocal"))
	require.Nil(t, cidrMatch.Insert("ff::/16", "testV6local"))

	search := func(s string) interface{} {
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

// BenchmarkCidrMatch_Search-4 9119133 130.6 ns/op 16 B/op 1 allocs/op
func BenchmarkCidrMatch_Search(b *testing.B) {
	cidrMatch := NewCidrMapper[string]()
	require.Nil(b, cidrMatch.Insert("10.2.2.1/18", "testIPv4"))
	require.Nil(b, cidrMatch.Insert("2001:0db8:0000:0000:1234:0000:0000:9abc/32", "testIPv6"))

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

// 2102 ns/op,2106 ns/op
// BenchmarkSingleTrie-4 9823910 128.0 ns/op 16 B/op  1 allocs/op
func BenchmarkSingleTrie(b *testing.B) {
	m := NewCidrMapper[string]()
	if err := m.singleInsert("127.0.0.1/28", "localhost"); err != nil {
		b.Error(err)
	}
	m.singleInsert("ff::/56", "")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			m.singleSearch("127.0.0.0")
		} else {
			m.singleSearch("ff::")
		}
	}
}
