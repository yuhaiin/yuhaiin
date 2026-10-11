package softether

import "strings"

// SoftEther's password authentication, from SoftEtherVPN/src/Cedar/Account.c
// (HashPassword) and src/Cedar/Sam.c (SecurePassword).
//
//	stored   = SHA0(password || UPPER(username))
//	on-wire  = SHA0(stored || server_random)
//
// The server keeps `stored` and never sees the password again; the client
// computes `stored` from what the user typed and answers the server's 20-octet
// challenge with `on-wire`. A recorded login is useless against a later session
// because the random changes, which is the whole of what this construction
// buys -- there is no forward secrecy and no mutual authentication in it.
//
// Four details, each of which this package previously had wrong, and none of
// which a veepin-to-veepin test could have caught because both ends were
// wrong in the same direction:
//
//   - **SHA-0, not SHA-1.** See sha0.go.
//   - **The username is uppercased**, so "Alice" and "alice" are one account.
//     StrUpper is ASCII-only in the reference, so this is too -- Unicode
//     case folding here would compute a different digest than the peer for any
//     username outside ASCII.
//   - **Password first, then username.** The concatenation order is
//     password||USERNAME, not username||password.
//   - **The challenge is concatenated, not XORed.** SecurePassword writes the
//     stored hash and the random one after the other into one buffer and
//     hashes the 40 octets. XOR would truncate the input to 20.

// hashPassword computes the stored form of a password: what a SoftEther server
// holds in its user database, and what a client derives before answering a
// challenge.
func hashPassword(username, password string) [sha0Size]byte {
	// ASCII uppercase only, matching the reference's StrUpper. strings.ToUpper
	// would also fold non-ASCII and produce a digest no SoftEther agrees with.
	return sha0([]byte(password + asciiUpper(username)))
}

// securePassword answers a server challenge with a stored hash.
func securePassword(stored [sha0Size]byte, random [sha0Size]byte) [sha0Size]byte {
	var buf [sha0Size * 2]byte
	copy(buf[:], stored[:])
	copy(buf[sha0Size:], random[:])
	return sha0(buf[:])
}

// asciiUpper uppercases the 26 ASCII letters and leaves every other octet
// alone, as StrUpper does.
func asciiUpper(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r >= 'a' && r <= 'z' }) {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
