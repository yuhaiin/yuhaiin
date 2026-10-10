// Adapted from xen0bit/veepin (MIT), Copyright (c) 2026 Remy. See THIRD_PARTY_LICENSE.
package native

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"
)

// TestSHA0MatchesTheFIPS180Vectors checks the published SHA-0 digests. If this
// fails the login digest is wrong and no real SoftEther server will accept it,
// which is a failure that otherwise only shows up in the interop cell.
func TestSHA0MatchesTheFIPS180Vectors(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The two FIPS 180 appendix examples, plus the empty string.
		{"abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "d2516ee1acfa5baf33dfc1c471e438449ef134c8"},
		{"", "f96cea198ad1dd5617ac084a3d92c6107708c0ef"},
		// A million 'a', the classic long-message vector, exercises the
		// multi-block path that the short ones above cannot.
		{strings.Repeat("a", 1000000), "3232affa48628a26653b5aaa44541fd90d690603"},
	} {
		got := sha0([]byte(tc.in))
		want, err := hex.DecodeString(tc.want)
		if err != nil {
			t.Fatalf("bad vector: %v", err)
		}
		if !bytes.Equal(got[:], want) {
			label := tc.in
			if len(label) > 32 {
				label = label[:32] + "..."
			}
			t.Errorf("sha0(%q) = %x, want %s", label, got, tc.want)
		}
	}
}

// TestSHA0IsNotSHA1 is the guard against the tidy-up that "fixes" sha0 by
// deleting it and calling crypto/sha1 instead. The two agree on nothing, and
// the failure that substitution causes is a rejected login against a real
// server and nothing at all against another veepin.
func TestSHA0IsNotSHA1(t *testing.T) {
	for _, in := range []string{"", "abc", "the quick brown fox"} {
		zero := sha0([]byte(in))
		one := sha1.Sum([]byte(in))
		if bytes.Equal(zero[:], one[:]) {
			t.Errorf("sha0(%q) == sha1(%q); the message schedule's missing ROTL1 is gone", in, in)
		}
	}
}

// TestSHA0BlockBoundaries walks the lengths where padding decides whether an
// extra block is emitted -- 55/56/57 and 63/64/65 octets. An off-by-one in the
// pad loop is invisible everywhere else.
func TestSHA0BlockBoundaries(t *testing.T) {
	seen := map[string]int{}
	for n := range 130 {
		d := sha0(bytes.Repeat([]byte{'x'}, n))
		key := hex.EncodeToString(d[:])
		if prev, dup := seen[key]; dup {
			t.Errorf("length %d and %d hash equal; the length padding is not being mixed in", prev, n)
		}
		seen[key] = n
	}
}
