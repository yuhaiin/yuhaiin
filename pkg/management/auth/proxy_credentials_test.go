package auth

import (
	"crypto/sha256"
    "crypto/rand"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/mschap"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func TestSSTPCredentialsScopeAndRevocation(t *testing.T) {
    store := testStore(t)
    admin := testUser(t, store, "admin", Admin)
    user := testUser(t, store, "alice", NoManagement)
    credentials, err := NewProxyCredentials(t.Context(), store)
    if err != nil { t.Fatal(err) }
    defer credentials.Close()

    issued, err := credentials.Issue(t.Context(), principal(admin), ProxyCredentialRequest{
        Owner: user.ID, Name: "laptop", Inbounds: []string{"sstp-entry"}, Protocols: []string{"sstp"},
    })
    if err != nil { t.Fatal(err) }
    var challenge, peer [16]byte
    if _, err := rand.Read(challenge[:]); err != nil { t.Fatal(err) }
    if _, err := rand.Read(peer[:]); err != nil { t.Fatal(err) }
    response := mschap.GenerateNTResponse(challenge, peer, user.Login, issued.Secret)
    verify := credentials.MSCHAPv2Verifier("sstp-entry", []string{user.ID})
    identity, hash, err := verify(t.Context(), user.Login, challenge, peer, response)
    if err != nil || identity.UserID != user.ID || identity.CredentialID != issued.ID ||
        hash != mschap.NTPasswordHash(issued.Secret) {
        t.Fatalf("invalid SSTP authentication result: %v", err)
    }
    for _, verifier := range []proxyauth.MSCHAPv2Verifier{
        credentials.MSCHAPv2Verifier("other-entry", []string{user.ID}),
        credentials.MSCHAPv2Verifier("sstp-entry", []string{admin.ID}),
    } {
        if _, _, err := verifier(t.Context(), user.Login, challenge, peer, response); err == nil {
            t.Fatal("out-of-scope credential accepted")
        }
    }
    if _, _, err := verify(t.Context(), "unknown", challenge, peer, response); err == nil {
        t.Fatal("unexpected username accepted")
    }
    response[0] ^= 0xff
    if _, _, err := verify(t.Context(), user.Login, challenge, peer, response); err == nil {
        t.Fatal("incorrect challenge response accepted")
    }
    if err := credentials.Revoke(t.Context(), principal(admin), issued.ID); err != nil { t.Fatal(err) }
    if identity.Valid() { t.Fatal("revoked identity remained valid") }
}

func TestDeleteProxyCredentialRemovesRecordAndCancelsSessions(t *testing.T) {
	for _, state := range []string{"active", "revoked", "expired"} {
		t.Run(state, func(t *testing.T) {
			s := testStore(t)
			admin := testUser(t, s, "admin", Admin)
			user := testUser(t, s, "alice", NoManagement)
			other := testUser(t, s, "bob", NoManagement)
			p, err := NewProxyCredentials(t.Context(), s)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			c, err := p.Issue(t.Context(), principal(user), ProxyCredentialRequest{Name: "phone"})
			if err != nil {
				t.Fatal(err)
			}
			verify := p.Verifier("entry", "http", []string{user.ID})
			identity, err := verify(t.Context(), user.Login, []byte(c.Secret))
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Delete(t.Context(), Principal{}, c.ID); !errors.Is(err, ErrForbidden) {
				t.Fatalf("delete without permissions: %v", err)
			}
			if err := p.Delete(t.Context(), principal(other), c.ID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("delete another owner's credential: %v", err)
			}
			if !identity.Valid() {
				t.Fatal("unauthorized deletion invalidated credential")
			}
			switch state {
			case "revoked":
				if err := p.Revoke(t.Context(), principal(user), c.ID); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if _, err := s.db.ExecContext(t.Context(), `UPDATE proxy_credentials SET expires_at=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), c.ID); err != nil {
					t.Fatal(err)
				}
			}
			actor := principal(user)
			if state == "expired" {
				actor = principal(admin)
			}
			if err := p.Delete(t.Context(), actor, c.ID); err != nil {
				t.Fatal(err)
			}
			if identity.Valid() {
				t.Fatal("deleted credential retained its sessions")
			}
			if _, err := verify(t.Context(), user.Login, []byte(c.Secret)); err == nil {
				t.Fatal("deleted credential authenticated")
			}
			list, err := p.List(t.Context(), user.ID)
			if err != nil || len(list) != 0 {
				t.Fatalf("deleted row retained: %+v, %v", list, err)
			}
			if err := p.Delete(t.Context(), actor, c.ID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("delete missing credential: %v", err)
			}
		})
	}
}

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
