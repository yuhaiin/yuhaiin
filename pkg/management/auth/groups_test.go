package auth

import (
	"errors"
	"slices"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func TestGroupAtomicMembershipsConflictAndAudit(t *testing.T) {
	s := testStore(t)
	a := testUser(t, s, "admin", Admin)
	u := testUser(t, s, "alice", NoManagement)
	actor := principal(a)
	request := GroupRequest{Name: "Finance", Description: "accounts", Members: []string{u.ID}}
	if _, err := s.SaveGroup(t.Context(), principal(u), "", request); !errors.Is(err, ErrForbidden) {
		t.Fatalf("self membership escalation: %v", err)
	}
	g, err := s.SaveGroup(t.Context(), actor, "", request)
	if err != nil {
		t.Fatal(err)
	}
	request.Name, request.Revision = "Finance renamed", g.Revision
	request.Members = []string{a.ID, "missing-user"}
	if _, err := s.SaveGroup(t.Context(), actor, g.ID, request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("dangling user: %v", err)
	}
	got, err := s.Group(t.Context(), g.ID)
	if err != nil || got.Name != g.Name || !slices.Equal(got.Members, g.Members) || got.Revision != g.Revision {
		t.Fatalf("partial update: %+v, %v", got, err)
	}
	request.Members = []string{a.ID, u.ID}
	updated, err := s.SaveGroup(t.Context(), actor, g.ID, request)
	if err != nil || updated.ID != g.ID || updated.Revision != 2 {
		t.Fatalf("update: %+v, %v", updated, err)
	}
	if _, err := s.SaveGroup(t.Context(), actor, g.ID, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if err := s.DeleteGroup(t.Context(), actor, g.ID, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if err := s.DeleteGroup(t.Context(), principal(u), g.ID, 2); !errors.Is(err, ErrForbidden) {
		t.Fatalf("self delete: %v", err)
	}
	if err := s.DeleteGroup(t.Context(), actor, g.ID, 2); err != nil {
		t.Fatal(err)
	}
	tombstone, err := s.Group(t.Context(), g.ID)
	if err != nil || !tombstone.Deleted || len(tombstone.Members) != 0 {
		t.Fatalf("deleted reference lost: %+v, %v", tombstone, err)
	}
	request.Revision = tombstone.Revision
	if _, err := s.SaveGroup(t.Context(), actor, g.ID, request); !errors.Is(err, ErrConflict) {
		t.Fatalf("resurrected deleted group: %v", err)
	}
	replacement, err := s.SaveGroup(t.Context(), actor, "", GroupRequest{Name: g.Name})
	if err != nil || replacement.ID == g.ID {
		t.Fatalf("reused group identity: %+v, %v", replacement, err)
	}
	var count int
	if err := s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM traffic_group_members`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("orphan members: %d, %v", count, err)
	}
	events, err := s.Events(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(events, func(event SecurityEvent) bool {
		return event.Event == "group.deleted" && event.SubjectID == g.ID && event.Changes != ""
	}) {
		t.Fatalf("historical group identifiers lost: %+v", events)
	}
}

func TestGroupChangesRevokeOnlyAffectedIdentities(t *testing.T) {
	s := testStore(t)
	a := testUser(t, s, "admin", Admin)
	u := testUser(t, s, "alice", NoManagement)
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	issue := func(user User) (IssuedProxyCredential, *proxyauth.Identity) {
		t.Helper()
		c, err := p.Issue(t.Context(), principal(user), ProxyCredentialRequest{Name: "phone"})
		if err != nil {
			t.Fatal(err)
		}
		i, err := p.Verifier("entry", "http", []string{user.ID})(t.Context(), user.Login, []byte(c.Secret))
		if err != nil {
			t.Fatal(err)
		}
		return c, i
	}
	_, unrelated := issue(a)
	c, before := issue(u)
	g, err := s.SaveGroup(t.Context(), principal(a), "", GroupRequest{Name: "Finance", Members: []string{u.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	if before.Valid() || !unrelated.Valid() {
		t.Fatal("membership change did not isolate revocation")
	}
	verify := p.Verifier("entry", "http", []string{u.ID})
	after, err := verify(t.Context(), u.Login, []byte(c.Secret))
	if err != nil || !slices.Equal(after.GroupIDs, []string{g.ID}) {
		t.Fatalf("membership snapshot: %+v, %v", after, err)
	}
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	if !after.Valid() {
		t.Fatal("unchanged reload revoked session")
	}
	second, err := s.SaveGroup(t.Context(), principal(a), "", GroupRequest{Name: "Engineering", Members: []string{u.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	if after.Valid() || !unrelated.Valid() {
		t.Fatal("overlapping membership revocation failed")
	}
	after, err = verify(t.Context(), u.Login, []byte(c.Secret))
	if err != nil || len(after.GroupIDs) != 2 || !slices.IsSorted(after.GroupIDs) {
		t.Fatalf("overlap: %+v, %v", after, err)
	}
	if err := s.DeleteGroup(t.Context(), principal(a), second.ID, second.Revision); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	if after.Valid() {
		t.Fatal("deleted membership retained access")
	}
	if err := s.DeleteUser(t.Context(), a.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.Group(t.Context(), g.ID)
	if err != nil || len(got.Members) != 0 {
		t.Fatalf("deleted user membership retained: %+v, %v", got, err)
	}
}

func TestCredentialsShareUnchangedOwnerMembershipSnapshots(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	if _, err := s.SaveGroup(t.Context(), principal(admin), "", GroupRequest{Name: "Finance", Members: []string{admin.ID}}); err != nil {
		t.Fatal(err)
	}
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	first, err := p.Issue(t.Context(), principal(admin), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	verify := p.Verifier("entry", "http", []string{admin.ID})
	a, err := verify(t.Context(), admin.Login, []byte(first.Secret))
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Issue(t.Context(), principal(admin), ProxyCredentialRequest{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := verify(t.Context(), admin.Login, []byte(second.Secret))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.GroupIDs) != 1 || len(b.GroupIDs) != 1 || &a.GroupIDs[0] != &b.GroupIDs[0] {
		t.Fatal("devices copied the owner's membership snapshot")
	}
	if !a.Valid() {
		t.Fatal("unchanged membership invalidated a credential")
	}
}
