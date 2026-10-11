package eap

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
)

// CredentialLookup returns the cleartext password for a username, and whether
// the user exists. Passwords are needed in cleartext (or as NT hashes) because
// MSCHAPv2 is a challenge/response scheme; there is no way to verify against a
// salted one-way hash.
type CredentialLookup func(username string) (password string, ok bool)

// Result reports the outcome of a completed EAP-MSCHAPv2 exchange.
type Result struct {
	Success  bool
	Username string
	// MSK is the 64-octet Master Session Key, used by IKEv2 as the shared
	// secret for the final AUTH payloads. Valid only when Success is true.
	MSK []byte
}

// authState is the server-side MSCHAPv2 state machine.
type authState int

const (
	stateInit authState = iota
	stateChallengeSent
	stateSuccessSent // waiting for the peer's success acknowledgement
	stateDone
)

// Server runs one EAP-MSCHAPv2 authentication as the authenticator. It is
// driven by feeding it the peer's EAP responses and emitting EAP requests.
type Server struct {
	lookup CredentialLookup
	name   string // server name placed in the Challenge

	state         authState
	eapID         uint8
	mschapID      uint8
	authChallenge [16]byte

	// Captured during the exchange for MSK derivation / success generation.
	username      string
	ntHash        []byte
	peerChallenge [16]byte
	ntResponse    [24]byte

	result Result
}

// NewServer creates an EAP-MSCHAPv2 authenticator. serverName is advertised in
// the challenge (clients largely ignore it).
func NewServer(lookup CredentialLookup, serverName string) *Server {
	return &Server{lookup: lookup, name: serverName, state: stateInit}
}

// Begin produces the first EAP request. For MSCHAPv2 we skip a separate
// Identity request and go straight to the Challenge, carrying the EAP
// identifier the IKE layer assigns. Many clients send an EAP Identity response
// first anyway; HandlePeer tolerates that.
func (s *Server) Begin(eapID uint8) (Packet, error) {
	if _, err := rand.Read(s.authChallenge[:]); err != nil {
		return Packet{}, err
	}
	s.eapID = eapID
	s.mschapID = eapID
	s.state = stateChallengeSent
	return Packet{
		Code:       CodeRequest,
		Identifier: eapID,
		Type:       TypeMSCHAPv2,
		Data:       mschapChallenge(s.mschapID, s.authChallenge, s.name),
	}, nil
}

// HandlePeer consumes an EAP response from the peer and returns the next EAP
// request to send. When authentication concludes, done is true and the Result
// is available via Outcome. The returned packet should still be sent (it may be
// an EAP-Success or EAP-Failure).
func (s *Server) HandlePeer(resp Packet) (next Packet, done bool, err error) {
	switch s.state {
	case stateChallengeSent:
		return s.handleResponseState(resp)
	case stateSuccessSent:
		// The peer acknowledges success with an MSCHAPv2 Success response
		// (opcode 3) or a bare EAP response; either way we finish with
		// EAP-Success.
		s.state = stateDone
		return Packet{Code: CodeSuccess, Identifier: resp.Identifier}, true, nil
	default:
		return Packet{}, false, fmt.Errorf("eap: unexpected state %d", s.state)
	}
}

func (s *Server) handleResponseState(resp Packet) (Packet, bool, error) {
	// A client may answer the Challenge with an EAP Identity response first
	// (Type 1). Re-issue the challenge in that case.
	if resp.Type == TypeIdentity {
		return Packet{
			Code:       CodeRequest,
			Identifier: s.eapID,
			Type:       TypeMSCHAPv2,
			Data:       mschapChallenge(s.mschapID, s.authChallenge, s.name),
		}, false, nil
	}
	if resp.Type == TypeNak {
		// The peer rejected MSCHAPv2 and proposed other methods; we only
		// support MSCHAPv2, so fail.
		s.result = Result{Success: false}
		s.state = stateDone
		return Packet{Code: CodeFailure, Identifier: resp.Identifier}, true,
			fmt.Errorf("eap: peer NAK'd MSCHAPv2")
	}
	if resp.Type != TypeMSCHAPv2 {
		return Packet{}, false, fmt.Errorf("eap: unexpected EAP type %d", resp.Type)
	}

	fields, err := parseMSCHAPResponse(resp.Data)
	if err != nil {
		return Packet{}, false, err
	}

	password, ok := s.lookup(fields.Name)
	if !ok {
		s.result = Result{Success: false, Username: fields.Name}
		s.state = stateDone
		return Packet{
			Code: CodeRequest, Identifier: nextID(resp.Identifier), Type: TypeMSCHAPv2,
			Data: mschapFailure(s.mschapID, "E=691 R=0 C=0 V=3 M=Authentication failed"),
		}, false, nil
	}

	ntHash := ntPasswordHash(password)
	expected := generateNTResponse(s.authChallenge, fields.PeerChallenge, fields.Name, ntHash)
	if subtle.ConstantTimeCompare(expected[:], fields.NTResponse[:]) != 1 {
		s.result = Result{Success: false, Username: fields.Name}
		s.state = stateDone
		return Packet{
			Code: CodeRequest, Identifier: nextID(resp.Identifier), Type: TypeMSCHAPv2,
			Data: mschapFailure(s.mschapID, "E=691 R=0 C=0 V=3 M=Authentication failed"),
		}, false, nil
	}

	// Success: capture material for MSK, emit an MSCHAPv2 Success request.
	s.username = fields.Name
	s.ntHash = ntHash
	s.peerChallenge = fields.PeerChallenge
	s.ntResponse = fields.NTResponse

	authResp := generateAuthenticatorResponse(ntHash, fields.NTResponse,
		fields.PeerChallenge, s.authChallenge, fields.Name)
	s.result = Result{
		Success:  true,
		Username: fields.Name,
		MSK:      deriveMSK(ntHash, fields.NTResponse),
	}
	s.state = stateSuccessSent
	return Packet{
		Code: CodeRequest, Identifier: nextID(resp.Identifier), Type: TypeMSCHAPv2,
		Data: mschapSuccess(s.mschapID, authResp),
	}, false, nil
}

// Outcome returns the authentication result once the exchange is complete.
func (s *Server) Outcome() Result { return s.result }

func nextID(id uint8) uint8 { return id + 1 }
