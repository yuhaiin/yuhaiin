package proxyauth

import (
	"context"
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
