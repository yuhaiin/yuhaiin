// Adapted from xen0bit/veepin (MIT), Copyright (c) 2026 Remy. See THIRD_PARTY_LICENSE.
package native

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

// TestHashPasswordUppercasesTheUsername pins the fold, because it decides
// whether two spellings of a name are one account. A server that skipped it
// would reject the reference client's login for "Alice" and accept it for
// "ALICE", which looks like a credential problem and is a hashing one.
func TestHashPasswordUppercasesTheUsername(t *testing.T) {
	lower := hashPassword("alice", "s3cret")
	mixed := hashPassword("Alice", "s3cret")
	upper := hashPassword("ALICE", "s3cret")
	if lower != mixed || lower != upper {
		t.Error("username case changes the digest; StrUpper is not being applied")
	}
}

// TestHashPasswordOrdersPasswordThenUsername catches the concatenation being
// written the other way round. Both orders are self-consistent, so only a
// comparison against the reference's order can tell them apart.
func TestHashPasswordOrdersPasswordThenUsername(t *testing.T) {
	// If the order were username||password, these two would collide: the
	// concatenation "ab"+"c" and "a"+"bc" are the same octets under one order
	// and different under the other.
	//
	// hashPassword(user, pass) = SHA0(pass + UPPER(user)), so:
	//   ("BC", "a")  -> SHA0("a" + "BC")  = SHA0("aBC")
	//   ("C", "aB")  -> SHA0("aB" + "C")  = SHA0("aBC")
	// Equal under the correct order, and unequal if the order is reversed.
	if hashPassword("BC", "a") != hashPassword("C", "aB") {
		t.Error("password and username are being concatenated in the wrong order")
	}
}

// TestSecurePasswordConcatenatesTheChallenge is the XOR guard. XOR of two
// 20-octet values is 20 octets; the concatenation the reference hashes is 40.
// Both produce a plausible digest and only one is accepted by a real server.
func TestSecurePasswordConcatenatesTheChallenge(t *testing.T) {
	stored := hashPassword("alice", "s3cret")
	var random [sha0Size]byte
	for i := range random {
		random[i] = byte(i)
	}

	got := securePassword(stored, random)

	var xored [sha0Size]byte
	for i := range stored {
		xored[i] = stored[i] ^ random[i]
	}
	xoredDigest := sha0(xored[:])
	if bytes.Equal(got[:], xoredDigest[:]) {
		t.Error("securePassword is hashing the XOR, not the concatenation")
	}

	var want [sha0Size * 2]byte
	copy(want[:], stored[:])
	copy(want[sha0Size:], random[:])
	wantDigest := sha0(want[:])
	if !bytes.Equal(got[:], wantDigest[:]) {
		t.Error("securePassword is not SHA0(stored || random)")
	}
}

// TestPasswordDigestIsNotSHA1 guards the whole chain against a well-meaning
// swap to the standard library.
func TestPasswordDigestIsNotSHA1(t *testing.T) {
	got := hashPassword("alice", "s3cret")
	sha1Version := sha1.Sum([]byte("s3cret" + "ALICE"))
	if bytes.Equal(got[:], sha1Version[:]) {
		t.Error("hashPassword is computing SHA-1; a real server will reject every login")
	}
}

// TestAsciiUpperLeavesNonASCIIAlone: the reference's StrUpper is byte-wise, so
// folding a non-ASCII username the way Go's strings.ToUpper does would derive
// a different digest than the peer for the same account.
func TestAsciiUpperLeavesNonASCIIAlone(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"alice", "ALICE"},
		{"Alice-99", "ALICE-99"},
		{"ärger", "äRGER"}, // ä is left as-is, unlike strings.ToUpper
		{"", ""},
	} {
		if got := asciiUpper(tc.in); got != tc.want {
			t.Errorf("asciiUpper(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
