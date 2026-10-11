package dtls

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

// The TLS 1.2 PRF (RFC 5246 section 5) and the key schedule built on it. DTLS
// 1.2 uses the TLS 1.2 constructions unchanged; only the record layer differs.

// newHash returns a constructor for the digest a suite's PRF and transcript use.
func (h hashID) new() hash.Hash {
	if h == hashSHA384 {
		return sha512.New384()
	}
	return sha256.New()
}

// prf is P_hash expanded to n octets: HMAC over a chain of A(i) values seeded
// with label||seed (RFC 5246 section 5).
func prf(h hashID, secret []byte, label string, seed []byte, n int) []byte {
	full := make([]byte, 0, len(label)+len(seed))
	full = append(full, label...)
	full = append(full, seed...)

	out := make([]byte, 0, n)
	// A(0) = seed; A(i) = HMAC(secret, A(i-1)).
	a := full
	for len(out) < n {
		mac := hmac.New(h.new, secret)
		mac.Write(a)
		a = mac.Sum(nil)

		mac.Reset()
		mac.Write(a)
		mac.Write(full)
		out = append(out, mac.Sum(nil)...)
	}
	return out[:n]
}

// pskPremaster builds the PSK premaster secret (RFC 4279 section 2): an
// all-zero block the length of the key, then the key itself, each with a 16-bit
// length prefix. There is no other key-exchange input, which is what makes this
// handshake so much smaller than a certificate-based one.
func pskPremaster(psk []byte) []byte {
	n := len(psk)
	out := make([]byte, 0, 2+n+2+n)
	out = binary.BigEndian.AppendUint16(out, uint16(n))
	out = append(out, make([]byte, n)...)
	out = binary.BigEndian.AppendUint16(out, uint16(n))
	out = append(out, psk...)
	return out
}

// masterSecret derives the master secret from the premaster and the two randoms.
func masterSecret(h hashID, premaster, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, 2*randomLen)
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)
	return prf(h, premaster, "master secret", seed, masterSecretLen)
}

// keyMaterial is the directional key material a connection encrypts with. For an
// AEAD suite there are no MAC keys — the cipher provides integrity — so the key
// block holds only the write keys and their implicit nonce salts.
type keyMaterial struct {
	clientKey, serverKey []byte
	clientIV, serverIV   []byte
}

// expandKeys derives the key block and splits it (RFC 5246 section 6.3). Note the
// seed is server_random||client_random here, the reverse of the master secret's
// order — a detail that produces a working handshake in neither direction if
// mirrored wrongly, since both ends make the same mistake and still agree.
func expandKeys(s suite, master, clientRandom, serverRandom []byte) keyMaterial {
	seed := make([]byte, 0, 2*randomLen)
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)
	block := prf(s.prfHash, master, "key expansion", seed, 2*s.keyLen+2*s.ivLen)

	var km keyMaterial
	off := 0
	km.clientKey = block[off : off+s.keyLen]
	off += s.keyLen
	km.serverKey = block[off : off+s.keyLen]
	off += s.keyLen
	km.clientIV = block[off : off+s.ivLen]
	off += s.ivLen
	km.serverIV = block[off : off+s.ivLen]
	return km
}

// finishedVerifyData is the Finished message's contents: a PRF over the hash of
// every handshake message exchanged so far, which is what binds the negotiation
// against tampering.
func finishedVerifyData(s suite, master []byte, label string, transcript []byte) []byte {
	h := s.prfHash.new()
	h.Write(transcript)
	return prf(s.prfHash, master, label, h.Sum(nil), verifyDataLen)
}

const (
	labelClientFinished = "client finished"
	labelServerFinished = "server finished"
)
