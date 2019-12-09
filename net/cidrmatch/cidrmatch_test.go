package cidrmatch

import (
	"os"
	"testing"
)

func TestCidrMatch_MatchWithTrie(t *testing.T) {
	cidrMatch, _ := NewCidrMatchWithTrie(os.Getenv("HOME") + "/.config/SSRSub/cidrBypass.conf")
	t.Log(cidrMatch.MatchWithTrie("10.2.2.1"))
}

func BenchmarkCidrMatch_MatchWithTrie(b *testing.B) {
	b.StopTimer()
	cidrMatch, _ := NewCidrMatchWithTrie(os.Getenv("HOME") + "/.config/SSRSub/cidrBypass.conf")
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		cidrMatch.MatchWithTrie("10.2.2.1")
	}
}
