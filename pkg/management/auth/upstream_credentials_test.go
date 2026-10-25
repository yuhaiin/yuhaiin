package auth

import (
	"context"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/credential"
)

func TestUpstreamSecretsAreIndependentAndRedacted(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	u := &UpstreamCredentials{store: s}
	var changed []string
	u.Changed = func(id string) { changed = append(changed, id) }
	request := UpstreamCredentialRequest{Name: "office", Type: credential.UsernamePassword, Username: "upstream-user", Password: "private-upstream-secret"}
	m, err := u.Save(t.Context(), principal(admin), "", request)
	if err != nil {
		t.Fatal(err)
	}
	value, revision, err := u.Lookup(t.Context(), m.ID)
	if err != nil || value != request.Value || revision != 1 {
		t.Fatalf("lookup: %+v %d %v", value, revision, err)
	}
	list, err := u.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(list)
	if strings.Contains(string(encoded), request.Password) || strings.Contains(string(encoded), request.Username) {
		t.Fatal("management list disclosed secret material")
	}
	request.Password = "rotated-secret"
	next, err := u.Save(t.Context(), principal(admin), m.ID, request)
	if err != nil || next.Revision != 2 {
		t.Fatalf("rotation: %+v %v", next, err)
	}
	if len(changed) != 2 || changed[0] != m.ID || changed[1] != m.ID {
		t.Fatal("cache invalidation missing")
	}
	reader := testUser(t, s, "reader", ReadOnly)
	if _, err := u.Save(t.Context(), principal(reader), "", request); err == nil {
		t.Fatal("reader stored an upstream secret")
	}
	if err := u.Delete(t.Context(), principal(admin), m.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := u.Lookup(t.Context(), m.ID); err == nil {
		t.Fatal("deleted secret resolved")
	}
}

func TestProxyCredentialSelfServiceCannotManageOtherOwners(t *testing.T) {
	s := testStore(t)
	a := testUser(t, s, "alice", NoManagement)
	b := testUser(t, s, "bob", NoManagement)
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	own, err := p.Issue(t.Context(), principal(a), ProxyCredentialRequest{Name: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	if own.UserID != a.ID {
		t.Fatal("wrong owner")
	}
	if _, err := p.Issue(t.Context(), principal(a), ProxyCredentialRequest{Owner: b.ID, Name: "other"}); err == nil {
		t.Fatal("issued credential for another owner")
	}
	if err := p.Revoke(t.Context(), principal(b), own.ID); err == nil {
		t.Fatal("revoked another owner's credential")
	}
	if _, err := p.Rotate(t.Context(), principal(b), own.ID); err == nil {
		t.Fatal("rotated another owner's credential")
	}
	if !principal(a).Allows(IdentityRead) || principal(a).Allows(NodesRead) || principal(a).Allows(TokensOwn) {
		t.Fatal("proxy user has management access")
	}
}

// Holding the only SQLite connection proves new outbound credential resolution
// uses the immutable snapshot, rather than timing an accidentally fast query.
func TestUpstreamLookupNoSQLAndRotationInvalidation(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	u := &UpstreamCredentials{store: s}
	request := UpstreamCredentialRequest{Name: "vpn", Type: credential.Password, Password: "old-secret"}
	m, err := u.Save(t.Context(), principal(admin), "", request)
	if err != nil {
		t.Fatal(err)
	}
	s.db.SetMaxOpenConns(1)
	conn, err := s.db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	for range 1000 {
		value, rev, err := u.Lookup(ctx, m.ID)
		if err != nil || value.Password != "old-secret" || rev != 1 {
			t.Fatal("lookup accessed SQL or lost snapshot", rev, err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	request.Password = "new-secret"
	u.Changed = func(id string) {
		value, revision, err := u.Lookup(t.Context(), id)
		if err != nil || value.Password != "new-secret" || revision != 2 {
			t.Fatal("notification preceded snapshot publication", revision, err)
		}
	}
	if _, err := u.Save(t.Context(), principal(admin), m.ID, request); err != nil {
		t.Fatal(err)
	}
	u.close()
	if _, _, err := u.Lookup(t.Context(), m.ID); err == nil {
		t.Fatal("closed runtime retained accessible secret")
	}
	if u.cache.Load() != nil {
		t.Fatal("closed runtime retained secret snapshot")
	}
}
