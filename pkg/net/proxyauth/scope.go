package proxyauth

import (
	"context"
	"sync"
)

// Scope ties credential identities to one listener configuration. Replacing or
// removing the listener cancels user sessions even when the protocol listener's
// Close method only stops accepting new sockets.
type Scope struct {
	mu         sync.Mutex
	closed     bool
	identities map[*Identity]scopedIdentity
}
type scopedIdentity struct {
	identity *Identity
	cancel   context.CancelFunc
}

func NewScope() *Scope { return &Scope{identities: make(map[*Identity]scopedIdentity)} }
func (s *Scope) Wrap(verify Verifier) Verifier {
	return func(ctx context.Context, user string, proof []byte) (*Identity, error) {
		identity, err := verify(ctx, user, proof)
		if err != nil || identity == nil {
			return identity, err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed || !identity.Valid() {
			return nil, ErrUnauthorized
		}
		if entry, ok := s.identities[identity]; ok {
			return entry.identity, nil
		}
		bound, cancel := context.WithCancel(identity.Context)
		entry := scopedIdentity{identity: &Identity{UserID: identity.UserID, CredentialID: identity.CredentialID, Context: bound}, cancel: cancel}
		s.identities[identity] = entry
		context.AfterFunc(bound, func() { s.mu.Lock(); defer s.mu.Unlock(); delete(s.identities, identity) })
		return entry.identity, nil
	}
}
// WrapMSCHAPv2 associates successful PPP authentication with this listener's
// revocable identities, including cancellation on listener shutdown.
func (s *Scope) WrapMSCHAPv2(verify MSCHAPv2Verifier) MSCHAPv2Verifier {
    return func(ctx context.Context, username string, serverChallenge, peerChallenge [16]byte, response [24]byte) (*Identity, [16]byte, error) {
        identity, hash, err := verify(ctx, username, serverChallenge, peerChallenge, response)
        if err != nil || identity == nil {
            return nil, [16]byte{}, ErrUnauthorized
        }
        scoped, err := s.bind(identity)
        if err != nil {
            return nil, [16]byte{}, err
        }
        return scoped, hash, nil
    }
}

func (s *Scope) bind(identity *Identity) (*Identity, error) {
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.closed || !identity.Valid() {
        return nil, ErrUnauthorized
    }
    if entry, ok := s.identities[identity]; ok {
        return entry.identity, nil
    }
    bound, cancel := context.WithCancel(identity.Context)
    entry := scopedIdentity{identity: &Identity{UserID: identity.UserID, CredentialID: identity.CredentialID, Context: bound}, cancel: cancel}
    s.identities[identity] = entry
    context.AfterFunc(bound, func() { s.mu.Lock(); defer s.mu.Unlock(); delete(s.identities, identity) })
    return entry.identity, nil
}

func (s *Scope) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, entry := range s.identities {
		entry.cancel()
	}
	clear(s.identities)
}
