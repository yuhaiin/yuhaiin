package ppp

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/mschap"
)

// CHAP codes (RFC 1994), reused by MS-CHAPv2.
const (
	chapChallenge = 1
	chapResponse  = 2
	chapSuccess   = 3
	chapFailure   = 4
)

// mschapFlagsLen and the response value layout (RFC 2759 section 6): a 49-octet
// value of PeerChallenge(16) | Reserved(8) | NTResponse(24) | Flags(1).
const mschapResponseValueLen = 16 + 8 + mschap.NTResponseLen + 1

// parseChallenge extracts the authenticator challenge and server name from an
// MS-CHAPv2 Challenge packet body (Value-Size | Value | Name).
func parseChallenge(body []byte) (authChallenge [mschap.ChallengeLen]byte, name string, ok bool) {
	if len(body) < 1 {
		return authChallenge, "", false
	}
	size := int(body[0])
	if size != mschap.ChallengeLen || len(body) < 1+size {
		return authChallenge, "", false
	}
	copy(authChallenge[:], body[1:1+size])
	return authChallenge, string(body[1+size:]), true
}

// buildResponse builds an MS-CHAPv2 Response packet body for the given
// challenge, generating a random peer challenge. It returns the body and the
// values needed later to verify the server and derive the HLAK.
func buildResponse(authChallenge [mschap.ChallengeLen]byte, username, password string) (body []byte, peerChallenge [mschap.ChallengeLen]byte, ntResponse [mschap.NTResponseLen]byte, err error) {
	if _, err = rand.Read(peerChallenge[:]); err != nil {
		return nil, peerChallenge, ntResponse, fmt.Errorf("ppp: peer challenge: %w", err)
	}
	ntResponse = mschap.GenerateNTResponse(authChallenge, peerChallenge, username, password)

	var value [mschapResponseValueLen]byte
	copy(value[:16], peerChallenge[:])
	// bytes 16..24 reserved (zero)
	copy(value[24:48], ntResponse[:])
	// byte 48 flags (zero)

	body = make([]byte, 0, 1+len(value)+len(username))
	body = append(body, byte(len(value)))
	body = append(body, value[:]...)
	body = append(body, username...)
	return body, peerChallenge, ntResponse, nil
}

// verifySuccess checks the server's MS-CHAPv2 Success message carries the
// authenticator response the client expects, proving the server knew the
// password. The Success body is "S=<40 hex>[ M=<message>]".
func verifySuccess(body []byte, authChallenge, peerChallenge [mschap.ChallengeLen]byte, username, password string, ntResponse [mschap.NTResponseLen]byte) error {
	msg := string(body)
	fields := strings.Fields(msg)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "S=") {
		return fmt.Errorf("ppp: malformed MS-CHAPv2 success %q", msg)
	}
	want := mschap.AuthenticatorResponse(authChallenge, peerChallenge, username, password, ntResponse)
	if !strings.EqualFold(fields[0], want) {
		return fmt.Errorf("%w: server authenticator mismatch", ErrAuth)
	}
	return nil
}

// buildChallenge builds the authenticator's MS-CHAPv2 Challenge packet body
// (Value-Size | Value | Name) — the server-role counterpart of parseChallenge.
func buildChallenge(authChallenge [mschap.ChallengeLen]byte, name string) []byte {
	body := make([]byte, 0, 1+mschap.ChallengeLen+len(name))
	body = append(body, mschap.ChallengeLen)
	body = append(body, authChallenge[:]...)
	body = append(body, name...)
	return body
}

// parseResponse decodes a client's MS-CHAPv2 Response body (Value-Size | Value |
// Name), extracting the peer challenge, NT response and username — the
// server-role counterpart of buildResponse.
func parseResponse(body []byte) (peerChallenge [mschap.ChallengeLen]byte, ntResponse [mschap.NTResponseLen]byte, username string, ok bool) {
	if len(body) < 1 {
		return peerChallenge, ntResponse, "", false
	}
	size := int(body[0])
	if size != mschapResponseValueLen || len(body) < 1+size {
		return peerChallenge, ntResponse, "", false
	}
	value := body[1 : 1+size]
	copy(peerChallenge[:], value[:16])
	// value[16:24] reserved
	copy(ntResponse[:], value[24:48])
	// value[48] flags
	return peerChallenge, ntResponse, string(body[1+size:]), true
}

// verifyResponse checks a client's NT response by recomputing it from the
// password the server holds; a match proves the client knew the password.
//
// The comparison is constant-time. Array equality in Go compiles to a
// short-circuiting memequal, which leaks through timing how many leading octets
// matched -- and this is the server's password check, so an attacker can retry
// it. The EAP server has always used a constant-time compare for exactly this
// value; this path had not, which is the kind of divergence a shared helper
// exists to prevent.
func verifyResponse(authChallenge, peerChallenge [mschap.ChallengeLen]byte, username, password string, ntResponse [mschap.NTResponseLen]byte) bool {
	want := mschap.GenerateNTResponse(authChallenge, peerChallenge, username, password)
	return cryptoutil.SecretEqual(want[:], ntResponse[:])
}

// buildSuccess builds the authenticator's MS-CHAPv2 Success body ("S=<40 hex>"),
// which proves to the client that the server also knew the password.
func buildSuccess(authChallenge, peerChallenge [mschap.ChallengeLen]byte, username, password string, ntResponse [mschap.NTResponseLen]byte) []byte {
	return []byte(mschap.AuthenticatorResponse(authChallenge, peerChallenge, username, password, ntResponse))
}

// buildFailure builds an MS-CHAPv2 Failure body for a rejected authentication.
// E=691 is ERROR_AUTHENTICATION_FAILURE.
func buildFailure() []byte {
	return []byte("E=691 R=0 C=00000000000000000000000000000000 V=3 M=Access denied")
}

// failureMessage extracts a human-readable reason from an MS-CHAPv2 Failure
// body ("E=<code> R=<r> ... M=<message>"), for error reporting.
func failureMessage(body []byte) string {
	s := string(body)
	if _, msg, ok := strings.Cut(s, "M="); ok {
		return strings.TrimSpace(msg)
	}
	return strings.TrimSpace(s)
}
