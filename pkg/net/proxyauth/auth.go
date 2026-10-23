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
	UserID       string `json:"userId"`
	CredentialID string `json:"credentialId"`
	// GroupIDs is a sorted, immutable membership snapshot. Membership changes
	// cancel this identity; callers must authenticate again for the new snapshot.
	GroupIDs []string        `json:"groupIds,omitempty"`
	Context  context.Context `json:"-"`
}

func (i *Identity) Valid() bool { return i == nil || (i.Context != nil && i.Context.Err() == nil) }

type Verifier func(context.Context, string, []byte) (*Identity, error)

type Provider interface {
	Verifier(inboundID, protocol string, allowedUsers []string) Verifier
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
