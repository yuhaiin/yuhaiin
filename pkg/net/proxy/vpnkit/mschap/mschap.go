// Package mschap implements the MS-CHAPv2 authentication primitives (RFC 2759)
// and the MPPE key derivation (RFC 3079) that a PPP client needs, plus the
// higher-layer authentication key (HLAK) SSTP's crypto binding is built from.
//
// It is deliberately transport-agnostic: it computes challenge responses,
// verifies the server's authenticator, and derives the MPPE master keys, but
// knows nothing of PPP framing or SSTP. The IKEv2 EAP server has its own
// MS-CHAPv2 path geared to deriving the IKEv2 MSK; this package instead derives
// the MPPE send/receive keys, which is what SSTP binds to the TLS channel.
//
// The constructions are from RFC 2759 (NT hash, challenge hash, NT response,
// authenticator response) and RFC 3079 section 3 (GetMasterKey,
// GetAsymmetricStartKey). All are little used elsewhere and easy to get subtly
// wrong, so each is covered by the RFCs' own test vectors.
package mschap

import (
	"crypto/cipher"
	"crypto/des"  //nolint:gosec // DES is required by the MS-CHAPv2 wire construction, not chosen for security
	"crypto/sha1" //nolint:gosec // SHA1 is required by MS-CHAPv2/MPPE, not chosen for security
	"encoding/binary"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // MD4 is required by NT hashing, not chosen for security
)

// ChallengeLen and related fixed sizes from RFC 2759.
const (
	ChallengeLen  = 16 // authenticator and peer challenges
	NTResponseLen = 24
	ntHashLen     = 16
)

// utf16LE encodes a password as UTF-16 little-endian, the form NT hashing runs
// MD4 over.
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// NTPasswordHash is MD4 of the UTF-16LE password (RFC 2759 NtPasswordHash).
func NTPasswordHash(password string) [ntHashLen]byte {
	return md4Sum(utf16LE(password))
}

// ntPasswordHashHash is MD4 of the NT hash (RFC 2759 HashNtPasswordHash); RFC
// 3079 calls it PasswordHashHash.
func ntPasswordHashHash(ntHash [ntHashLen]byte) [ntHashLen]byte {
	return md4Sum(ntHash[:])
}

func md4Sum(b []byte) [16]byte {
	h := md4.New()
	h.Write(b)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ChallengeHash is SHA1(PeerChallenge | AuthenticatorChallenge | UserName)
// truncated to 8 octets (RFC 2759 section 8.2). UserName is the bare account
// name, as sent in the response.
func ChallengeHash(peerChallenge, authChallenge [ChallengeLen]byte, username string) [8]byte {
	h := sha1.New()
	h.Write(peerChallenge[:])
	h.Write(authChallenge[:])
	h.Write([]byte(username))
	var out [8]byte
	copy(out[:], h.Sum(nil))
	return out
}

// GenerateNTResponse builds the 24-octet NT response (RFC 2759 section 8.1): the
// 8-octet challenge hash encrypted with the NT password hash under three DES
// keys.
func GenerateNTResponse(authChallenge, peerChallenge [ChallengeLen]byte, username, password string) [NTResponseLen]byte {
	challenge := ChallengeHash(peerChallenge, authChallenge, username)
	passwordHash := NTPasswordHash(password)
	return challengeResponse(challenge, passwordHash)
}

// challengeResponse is RFC 2759 section 8.5: pad the 16-octet hash to 21, split
// into three 7-octet DES keys, and encrypt the challenge under each.
func challengeResponse(challenge [8]byte, passwordHash [ntHashLen]byte) [NTResponseLen]byte {
	var z [21]byte
	copy(z[:], passwordHash[:])
	var resp [NTResponseLen]byte
	for i := range 3 {
		block := desBlock(z[i*7 : i*7+7])
		block.Encrypt(resp[i*8:], challenge[:])
	}
	return resp
}

// desBlock expands a 7-octet key to the 8-octet form DES needs (each octet
// carries 7 key bits plus a parity bit, which DES ignores) and returns the
// cipher.
func desBlock(key7 []byte) cipher.Block {
	var k [8]byte
	k[0] = key7[0]
	k[1] = key7[0]<<7 | key7[1]>>1
	k[2] = key7[1]<<6 | key7[2]>>2
	k[3] = key7[2]<<5 | key7[3]>>3
	k[4] = key7[3]<<4 | key7[4]>>4
	k[5] = key7[4]<<3 | key7[5]>>5
	k[6] = key7[5]<<2 | key7[6]>>6
	k[7] = key7[6] << 1
	block, err := des.NewCipher(k[:]) //nolint:gosec // see package doc: DES is the wire requirement
	if err != nil {
		panic("mschap: des key: " + err.Error()) // an 8-byte key never errors
	}
	return block
}

var (
	magicSigning = []byte("Magic server to client signing constant")
	magicPad     = []byte("Pad to make it do more than one iteration")
)

// AuthenticatorResponse builds the server's expected "S=<40 hex>" authenticator
// response (RFC 2759 section 8.7), so the client can verify the server proved
// knowledge of the password.
func AuthenticatorResponse(authChallenge, peerChallenge [ChallengeLen]byte, username, password string, ntResponse [NTResponseLen]byte) string {
	passwordHash := NTPasswordHash(password)
	passwordHashHash := ntPasswordHashHash(passwordHash)

	h := sha1.New()
	h.Write(passwordHashHash[:])
	h.Write(ntResponse[:])
	h.Write(magicSigning)
	digest := h.Sum(nil)

	challenge := ChallengeHash(peerChallenge, authChallenge, username)
	h.Reset()
	h.Write(digest)
	h.Write(challenge[:])
	h.Write(magicPad)
	digest = h.Sum(nil)

	return "S=" + strings.ToUpper(hexEncode(digest))
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
