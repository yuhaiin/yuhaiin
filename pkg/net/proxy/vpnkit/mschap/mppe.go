package mschap

import (
	"crypto/sha1" //nolint:gosec // SHA1 is required by the MPPE key derivation, not chosen for security
)

// HLAKLen is the size of the SSTP higher-layer authentication key: the two
// 16-octet MPPE master keys concatenated.
const HLAKLen = 32

// MPPE key-derivation constants (RFC 3079 section 3).
var (
	magicMaster  = []byte("This is the MPPE Master Key")
	magicSend    = []byte("On the client side, this is the send key; on the server side, it is the receive key.")
	magicReceive = []byte("On the client side, this is the receive key; on the server side, it is the send key.")
	shsPad1      = make([]byte, 40)      // 40 octets of 0x00
	shsPad2      = bytesRepeat(0xf2, 40) // 40 octets of 0xf2
)

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// getMasterKey is RFC 3079 GetMasterKey: SHA1(PasswordHashHash | NTResponse |
// Magic1) truncated to 16 octets.
func getMasterKey(passwordHashHash [ntHashLen]byte, ntResponse [NTResponseLen]byte) [16]byte {
	h := sha1.New()
	h.Write(passwordHashHash[:])
	h.Write(ntResponse[:])
	h.Write(magicMaster)
	var mk [16]byte
	copy(mk[:], h.Sum(nil))
	return mk
}

// getAsymmetricStartKey is RFC 3079 GetAsymmetricStartKey: SHA1(MasterKey |
// SHSpad1 | Magic | SHSpad2) truncated to keyLen. The send/receive choice
// depends on the side; magicSend is used when isSend and isServer differ (so a
// client's send key uses magicSend, its receive key magicReceive).
func getAsymmetricStartKey(masterKey [16]byte, keyLen int, isSend, isServer bool) []byte {
	magic := magicReceive
	if isSend != isServer {
		magic = magicSend
	}
	h := sha1.New()
	h.Write(masterKey[:])
	h.Write(shsPad1)
	h.Write(magic)
	h.Write(shsPad2)
	return h.Sum(nil)[:keyLen]
}

// ClientHLAK derives the SSTP client's higher-layer authentication key from a
// completed MS-CHAPv2 exchange: the client's MPPE MasterSendKey concatenated
// with its MasterReceiveKey (MS-SSTP section 3.2.5.2.2).
//
//	ClientHLAK = ClientSendKey || ClientReceiveKey
func ClientHLAK(password string, ntResponse [NTResponseLen]byte) [HLAKLen]byte {
	passwordHash := NTPasswordHash(password)
	passwordHashHash := ntPasswordHashHash(passwordHash)
	masterKey := getMasterKey(passwordHashHash, ntResponse)

	send := getAsymmetricStartKey(masterKey, 16, true, false)
	recv := getAsymmetricStartKey(masterKey, 16, false, false)

	var hlak [HLAKLen]byte
	copy(hlak[:16], send)
	copy(hlak[16:], recv)
	return hlak
}
