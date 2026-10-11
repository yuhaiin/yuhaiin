package eap

import "crypto/rand"

// ClientChallenge holds the parsed fields of an MSCHAPv2 Challenge request that
// a client needs in order to build its response.
type ClientChallenge struct {
	MSCHAPID      uint8
	AuthChallenge [16]byte
	ServerName    string
}

// ParseChallenge extracts the MSCHAPv2 Challenge fields from an EAP request's
// type-data. It returns an error if the packet is not an MSCHAPv2 Challenge.
func ParseChallenge(eapData []byte) (ClientChallenge, bool) {
	if len(eapData) < 5+16 || mschapOpcode(eapData[0]) != opChallenge {
		return ClientChallenge{}, false
	}
	var c ClientChallenge
	c.MSCHAPID = eapData[1]
	copy(c.AuthChallenge[:], eapData[5:21])
	c.ServerName = string(eapData[21:])
	return c, true
}

// BuildResponse constructs the MSCHAPv2 Response type-data for the given
// credentials, generating a random peer challenge. It also returns the client's
// view of the MSK (identical to the server's on success), for callers that need
// to derive the final IKEv2 AUTH key.
func (c ClientChallenge) BuildResponse(username, password string) (respData []byte, msk []byte) {
	var peerChallenge [16]byte
	_, _ = rand.Read(peerChallenge[:])

	ntHash := ntPasswordHash(password)
	ntResp := generateNTResponse(c.AuthChallenge, peerChallenge, username, ntHash)

	resp := make([]byte, 5)
	resp[0] = byte(opResponse)
	resp[1] = c.MSCHAPID
	resp[4] = 49
	resp = append(resp, peerChallenge[:]...)
	resp = append(resp, make([]byte, 8)...) // reserved
	resp = append(resp, ntResp[:]...)
	resp = append(resp, 0x00) // flags
	resp = append(resp, []byte(username)...)
	msLen := len(resp)
	resp[2] = byte(msLen >> 8)
	resp[3] = byte(msLen)

	return resp, deriveMSK(ntHash, ntResp)
}

// SuccessResponseData returns the type-data for a client's acknowledgement of an
// MSCHAPv2 Success (opcode 3), which the client sends after verifying the
// server's authenticator response.
func SuccessResponseData() []byte {
	return []byte{byte(opSuccess)}
}
