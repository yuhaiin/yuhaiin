// Package proxyauth defines optional traffic authentication capabilities.
// It has no dependency on the management identity implementation.
package proxyauth

import (
	"context"
	"crypto/subtle"
	"errors"
)

var ErrUnauthorized = errors.New("proxy authentication failed")

// Identity contains no authentication secret. Context is canceled on expiry,
// revocation, user disablement, or module shutdown.
type Identity struct {
	UserID       string          `json:"userId"`
	CredentialID string          `json:"credentialId"`
	Context      context.Context `json:"-"`
}

func (i *Identity) Valid() bool { return i == nil || (i.Context != nil && i.Context.Err() == nil) }

type Verifier func(context.Context, string, []byte) (*Identity, error)

type Provider interface {
	Verifier(inboundID, protocol string, allowedUsers []string) Verifier
}

// MSCHAPv2Verifier checks a challenge response against device credentials.
// The NT hash returned on success is password-equivalent; callers must use it
// only to finish the current PPP/SSTP handshake.
type MSCHAPv2Verifier func(ctx context.Context, username string, serverChallenge, peerChallenge [16]byte, response [24]byte) (*Identity, [16]byte, error)

// MSCHAPv2Provider is an optional capability of the existing identity provider.
type MSCHAPv2Provider interface {
	MSCHAPv2Verifier(inboundID string, allowedUsers []string) MSCHAPv2Verifier
}

// Check preserves the legacy partial-username/password matching rules. With a
// verifier installed an empty legacy configuration never permits anonymous use.
func Check(ctx context.Context, verify Verifier, username string, proof []byte, legacyUser, legacyPassword string) (*Identity, error) {
	if (legacyUser != "" || legacyPassword != "") &&
		(legacyUser == "" || subtle.ConstantTimeCompare([]byte(legacyUser), []byte(username)) == 1) &&
		(legacyPassword == "" || subtle.ConstantTimeCompare([]byte(legacyPassword), proof) == 1) {
		return nil, nil
	}
	if verify != nil {
		return verify(ctx, username, proof)
	}
	return nil, ErrUnauthorized
}
