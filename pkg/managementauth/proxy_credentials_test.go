package managementauth

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func TestMultipleProxyCredentialsScopesRotationAndDisable(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	user, enrollment, err := s.CreateUser(t.Context(), admin.ID, "alice", NoManagement, false)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.Secret == "" || principal(user).Allows(NodesRead) {
		t.Fatal("proxy user received management access")
	}
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	issue := func(name string) IssuedProxyCredential {
		t.Helper()
		c, err := p.Issue(t.Context(), principal(admin), ProxyCredentialRequest{Owner: user.ID, Name: name, Inbounds: []string{"entry"}, Protocols: []string{"socks5", "yuubinsya"}})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	phone, laptop := issue("phone"), issue("laptop")
	verify := p.Verifier("entry", "socks5", []string{user.ID})
	first, err := verify(t.Context(), "ALICE", []byte(phone.Secret))
	if err != nil || first.UserID != user.ID {
		t.Fatalf("identity %+v: %v", first, err)
	}
	if _, err := verify(t.Context(), "alice", []byte(laptop.Secret)); err != nil {
		t.Fatal(err)
	}
	for _, v := range []proxyauth.Verifier{p.Verifier("other", "socks5", []string{user.ID}), p.Verifier("entry", "http", []string{user.ID}), p.Verifier("entry", "socks5", nil)} {
		if _, err := v(t.Context(), "alice", []byte(phone.Secret)); err == nil {
			t.Fatal("scope accepted")
		}
	}
	if _, err := verify(t.Context(), "bob", []byte(phone.Secret)); err == nil {
		t.Fatal("wrong login accepted")
	}
	wire := sha256.Sum256([]byte(phone.Secret + "+s@1t"))
	if _, err := p.Verifier("entry", "yuubinsya", []string{user.ID})(t.Context(), "", wire[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), phone.Secret, "token"); err == nil {
		t.Fatal("proxy credential accepted for management")
	}
	rotated, err := p.Rotate(t.Context(), principal(admin), phone.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.Valid() {
		t.Fatal("rotated session retained access")
	}
	if _, err := verify(t.Context(), "alice", []byte(phone.Secret)); err == nil {
		t.Fatal("old secret accepted")
	}
	if _, err := verify(t.Context(), "alice", []byte(rotated.Secret)); err != nil {
		t.Fatal(err)
	}
	if err := p.Revoke(t.Context(), principal(admin), laptop.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t.Context(), "alice", []byte(laptop.Secret)); err == nil {
		t.Fatal("revoked credential accepted")
	}
	if err := s.UpdateUser(t.Context(), admin.ID, user.ID, user.Login, user.Role, true); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t.Context(), "alice", []byte(rotated.Secret)); err == nil {
		t.Fatal("disabled user accepted")
	}
	if err := s.UpdateUser(t.Context(), admin.ID, user.ID, user.Login, user.Role, false); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := verify(t.Context(), "alice", []byte(rotated.Secret)); err == nil {
		t.Fatal("reenable resurrected credential")
	}
}

func TestProxyCredentialExpiresWithoutDatabasePolling(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	p, err := NewProxyCredentials(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	c, err := p.Issue(t.Context(), principal(admin), ProxyCredentialRequest{Owner: admin.ID, Name: "short", ExpiresAt: time.Now().Add(2 * time.Second).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := p.Verifier("entry", "http", []string{admin.ID})(t.Context(), admin.Login, []byte(c.Secret))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-identity.Context.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("identity did not expire")
	}
}
