package cryptoutil

// Comparing secrets.
//
// Every protocol here has at least one place where it checks a value the peer
// supplied against one it computed: an MS-CHAPv2 response, an authentication
// proof, a packet tag. Those comparisons must not leak, through timing, how much
// of the value was correct — an attacker who learns "the first byte matched"
// can recover the whole thing byte by byte instead of guessing it at once.
//
// This existing as a named function is the point. Before it, each site decided
// independently, and they did not all decide the same way: the EAP server used
// subtle.ConstantTimeCompare while the PPP server used == on a fixed-size array,
// for the same MS-CHAPv2 response. A shared helper makes the next site correct
// by default and makes the wrong choice visible in review.

import "crypto/subtle"

// SecretEqual reports whether two secret-derived values are equal, in time that
// does not depend on how much of them matches.
//
// Use it for anything an attacker can supply and retry: authentication
// responses, MACs, tags, proofs. Length is not secret — a mismatch there is
// reported immediately, since the sizes involved are fixed by the protocol and
// visible on the wire anyway.
func SecretEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
