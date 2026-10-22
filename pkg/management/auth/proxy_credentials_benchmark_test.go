package auth

import (
	"path/filepath"
	"testing"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func BenchmarkProxyCredentialVerification(b *testing.B) {
	db, err := storagesqlite.OpenManagement(b.Context(), filepath.Join(b.TempDir(), "management.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	s := NewStore(db.DB())
	u, _, err := s.CreateUser(b.Context(), "local", "admin", Admin, true)
	if err != nil {
		b.Fatal(err)
	}
	p, err := NewProxyCredentials(b.Context(), s)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()
	issued, err := p.Issue(b.Context(), principal(u), ProxyCredentialRequest{Name: "phone", Owner: u.ID})
	if err != nil {
		b.Fatal(err)
	}
	verify := p.Verifier("entry", "socks5", []string{u.ID})
	proof := []byte(issued.Secret)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := verify(b.Context(), u.Login, proof); err != nil {
			b.Fatal(err)
		}
	}
}
