package mschap

import "testing"

func TestMSCHAPFromNTHashMatchesPassword(t *testing.T) {
	password := "yp_demo_secret_for_test"
	username := "alice"
	var authenticator, peer [ChallengeLen]byte
	for i := range authenticator {
		authenticator[i] = byte(i + 1)
		peer[i] = byte(0xf0 - i)
	}

	response := GenerateNTResponse(authenticator, peer, username, password)
	hash := NTPasswordHash(password)
	if got := GenerateNTResponseFromHash(authenticator, peer, username, hash); got != response {
		t.Fatal("NT response mismatch")
	}
	if got := AuthenticatorResponseFromHash(authenticator, peer, username, hash, response); got != AuthenticatorResponse(authenticator, peer, username, password, response) {
		t.Fatal("authenticator response mismatch")
	}
	if got := ClientHLAKFromHash(hash, response); got != ClientHLAK(password, response) {
		t.Fatal("SSTP binding key mismatch")
	}
}
