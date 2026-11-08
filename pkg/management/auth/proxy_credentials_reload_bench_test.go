package auth

import (
	"fmt"
	"path/filepath"
	"testing"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// An idle second used to cost one Reload; now it costs one changes() query.
func BenchmarkProxyCredentialsIdleTick(b *testing.B) {
	db, err := storagesqlite.OpenManagement(b.Context(), filepath.Join(b.TempDir(), "management.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	s := NewStore(db.DB())
	admin, _, err := s.CreateUser(b.Context(), "local", "admin", Admin, true)
	if err != nil {
		b.Fatal(err)
	}
	p, err := NewProxyCredentials(b.Context(), s)
	if err != nil {
		b.Fatal(err)
	}
	defer p.Close()
	for i := range 64 {
		u, _, err := s.CreateUser(b.Context(), "local", fmt.Sprint("user", i), NoManagement, false)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := p.Issue(b.Context(), principal(admin), ProxyCredentialRequest{Name: "device", Owner: u.ID}); err != nil {
			b.Fatal(err)
		}
	}
	b.Run("Reload", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := p.Reload(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("changes", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := s.changes(b.Context()); err != nil {
				b.Fatal(err)
			}
		}
	})
}
