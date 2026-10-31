package proxyauth

import (
	"context"
	"slices"
	"testing"
)

func TestListenerScopeDoesNotRevokeAnotherInbound(t *testing.T) {
	root := &Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}
	verify := func(context.Context, string, []byte) (*Identity, error) { return root, nil }
	first, second := NewScope(), NewScope()
	defer second.Close()
	a, err := first.Wrap(verify)(t.Context(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Wrap(verify)(t.Context(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	if a.Valid() || !b.Valid() || !root.Valid() {
		t.Fatal("listener cancellation crossed inbound scope")
	}
	if _, err := first.Wrap(verify)(t.Context(), "", nil); err == nil {
		t.Fatal("closed listener authenticated a user")
	}
}

func TestSSTPListenerScopePreservesTrafficGroups(t *testing.T) {
	root := &Identity{UserID: "alice", CredentialID: "phone", GroupIDs: []string{"finance"}, Context: t.Context()}
	proof := [16]byte{1, 2, 3}
	verify := func(context.Context, string, [16]byte, [16]byte, [24]byte) (*Identity, [16]byte, error) {
		return root, proof, nil
	}
	scope := NewScope()
	defer scope.Close()
	identity, hash, err := scope.WrapMSCHAPv2(verify)(t.Context(), "alice", [16]byte{}, [16]byte{}, [24]byte{})
	if err != nil || identity == nil {
		t.Fatal(err)
	}
	if identity.UserID != root.UserID || identity.CredentialID != root.CredentialID || !slices.Equal(identity.GroupIDs, root.GroupIDs) || hash != proof {
		t.Fatal("SSTP authentication lost identity or group policy")
	}
	shared, err := scope.Wrap(func(context.Context, string, []byte) (*Identity, error) { return root, nil })(t.Context(), "alice", nil)
	if err != nil || shared != identity {
		t.Fatal("listener verifier paths disagree on identity", err)
	}
	scope.Close()
	if identity.Valid() || !root.Valid() {
		t.Fatal("SSTP listener revocation escaped its scope")
	}
}
