package eap

import (
	"crypto/des"
	"crypto/sha1"
)

// ntPasswordHash computes MD4(UTF-16LE(password)) — the NT hash (RFC 2759
// section 8.3). The result is 16 octets.
func ntPasswordHash(password string) []byte {
	uni := utf16LE(password)
	h := md4(uni)
	return h[:]
}

// ntPasswordHashHash computes MD4 of the NT hash (RFC 2759 section 8.4).
func ntPasswordHashHash(ntHash []byte) []byte {
	h := md4(ntHash)
	return h[:]
}

// utf16LE encodes an ASCII/Latin-1 password as little-endian UTF-16, as
// MSCHAPv2 requires. Passwords are treated as a sequence of runes.
func utf16LE(s string) []byte {
	runes := []rune(s)
	out := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// challengeHash computes SHA1(PeerChallenge | AuthenticatorChallenge |
// UserName)[:8] (RFC 2759 section 8.2).
func challengeHash(peerChallenge, authChallenge [16]byte, username string) [8]byte {
	h := sha1.New()
	h.Write(peerChallenge[:])
	h.Write(authChallenge[:])
	h.Write([]byte(username))
	sum := h.Sum(nil)
	var out [8]byte
	copy(out[:], sum[:8])
	return out
}

// generateNTResponse computes the 24-octet NT-Response (RFC 2759 section 8.1):
// challengeResponse(ChallengeHash, NtPasswordHash).
func generateNTResponse(authChallenge, peerChallenge [16]byte, username string, ntHash []byte) [24]byte {
	ch := challengeHash(peerChallenge, authChallenge, username)
	return challengeResponse(ch, ntHash)
}

// challengeResponse implements the DES-based ChallengeResponse (RFC 2759
// section 8.5): the 16-octet (zero-padded to 21) hash is split into three
// 7-octet DES keys, each encrypting the 8-octet challenge.
func challengeResponse(challenge [8]byte, passwordHash []byte) [24]byte {
	var zpwd [21]byte
	copy(zpwd[:], passwordHash)

	var resp [24]byte
	copy(resp[0:8], desEncrypt(zpwd[0:7], challenge[:]))
	copy(resp[8:16], desEncrypt(zpwd[7:14], challenge[:]))
	copy(resp[16:24], desEncrypt(zpwd[14:21], challenge[:]))
	return resp
}

// desEncrypt turns a 7-octet key into a 56-bit DES key (adding parity bits) and
// ECB-encrypts the 8-octet block.
func desEncrypt(key7, block []byte) []byte {
	key8 := expandDESKey(key7)
	c, err := des.NewCipher(key8)
	if err != nil {
		return make([]byte, 8)
	}
	out := make([]byte, 8)
	c.Encrypt(out, block)
	return out
}

// expandDESKey converts a 7-octet key to 8 octets by inserting a parity bit
// after every 7 data bits (the low bit is parity and is ignored by DES).
func expandDESKey(key7 []byte) []byte {
	var k [8]byte
	k[0] = key7[0]
	k[1] = key7[0]<<7 | key7[1]>>1
	k[2] = key7[1]<<6 | key7[2]>>2
	k[3] = key7[2]<<5 | key7[3]>>3
	k[4] = key7[3]<<4 | key7[4]>>4
	k[5] = key7[4]<<3 | key7[5]>>5
	k[6] = key7[5]<<2 | key7[6]>>6
	k[7] = key7[6] << 1
	// The low bit of each octet is a parity bit; DES ignores it, so leaving it
	// zero is fine.
	return k[:]
}

// Magic constants from RFC 2759 section 8.7 for GenerateAuthenticatorResponse.
var (
	authMagic1 = []byte("Magic server to client signing constant")
	authMagic2 = []byte("Pad to make it do more than one iteration")
)

// generateAuthenticatorResponse computes the 20-octet Authenticator Response
// ("S=..." success value) per RFC 2759 section 8.7.
func generateAuthenticatorResponse(ntHash []byte, ntResponse [24]byte,
	peerChallenge, authChallenge [16]byte, username string) []byte {

	hashHash := ntPasswordHashHash(ntHash)

	h1 := sha1.New()
	h1.Write(hashHash)
	h1.Write(ntResponse[:])
	h1.Write(authMagic1)
	digest := h1.Sum(nil)

	ch := challengeHash(peerChallenge, authChallenge, username)

	h2 := sha1.New()
	h2.Write(digest)
	h2.Write(ch[:])
	h2.Write(authMagic2)
	return h2.Sum(nil) // 20 octets
}

// Magic constants from RFC 3079 section 3.3, defined as their exact ASCII
// strings to avoid transcription errors. magic2 is used for the send key on the
// client / receive key on the server; magic3 is the mirror.
var (
	magicMaster = []byte("This is the MPPE Master Key")
	magic2      = []byte("On the client side, this is the send key; " +
		"on the server side, it is the receive key.")
	magic3 = []byte("On the client side, this is the receive key; " +
		"on the server side, it is the send key.")
	shaPad1 = bytesRepeat(0x00, 40)
	shaPad2 = bytesRepeat(0xf2, 40)
)

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// getMasterKey derives the 16-octet MPPE master key (RFC 3079 section 3.3).
func getMasterKey(passwordHashHash []byte, ntResponse [24]byte) []byte {
	h := sha1.New()
	h.Write(passwordHashHash)
	h.Write(ntResponse[:])
	h.Write(magicMaster)
	sum := h.Sum(nil)
	return sum[:16]
}

// getAsymmetricStartKey derives a session key from the master key (RFC 3079
// section 3.3). The magic string is chosen by (isSend, isServer).
func getAsymmetricStartKey(masterKey []byte, keyLen int, isSend, isServer bool) []byte {
	// send: server->magic3, client->magic2 ; recv: server->magic2, client->magic3
	var s []byte
	if isSend {
		if isServer {
			s = magic3
		} else {
			s = magic2
		}
	} else {
		if isServer {
			s = magic2
		} else {
			s = magic3
		}
	}
	h := sha1.New()
	h.Write(masterKey)
	h.Write(shaPad1)
	h.Write(s)
	h.Write(shaPad2)
	sum := h.Sum(nil)
	if keyLen > len(sum) {
		keyLen = len(sum)
	}
	return sum[:keyLen]
}

// deriveMSK computes the 64-octet EAP-MSCHAPv2 MSK: the 16-octet send and
// receive master session keys, concatenated (recv||send per common
// implementations) and zero-padded to 64 octets. IKEv2 uses this MSK in place
// of the shared secret when computing the final AUTH payloads.
//
// The ordering follows the widely deployed convention (strongSwan, Windows):
// MSK = MasterReceiveKey(16) || MasterSendKey(16) || 32 zero octets, from the
// server's perspective as authenticator.
func deriveMSK(ntHash []byte, ntResponse [24]byte) []byte {
	hashHash := ntPasswordHashHash(ntHash)
	masterKey := getMasterKey(hashHash, ntResponse)
	// From the authenticator (server) perspective: MSK = recv || send.
	recvKey := getAsymmetricStartKey(masterKey, 16, false, true)
	sendKey := getAsymmetricStartKey(masterKey, 16, true, true)
	msk := make([]byte, 64)
	copy(msk[0:16], recvKey)
	copy(msk[16:32], sendKey)
	return msk
}
