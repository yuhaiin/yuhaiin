package auth

import (
	"path/filepath"
	"testing"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

// The periodic reload is skipped while the fingerprint is stable, so every
// commit, in-process or from another process, must move it.
func TestStoreChangesTracksCommits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	db, err := storagesqlite.OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewStore(db.DB())

	first, err := s.changes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if again, err := s.changes(t.Context()); err != nil || again != first {
		t.Fatalf("idle fingerprint moved: %v -> %v (%v)", first, again, err)
	}

	user := testUser(t, s, "alice", NoManagement)
	local, err := s.changes(t.Context())
	if err != nil || local == first {
		t.Fatalf("in-process write not observed: %v -> %v (%v)", first, local, err)
	}

	other, err := storagesqlite.OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.DB().ExecContext(t.Context(), `UPDATE management_users SET disabled=1 WHERE id=?`, user.ID); err != nil {
		t.Fatal(err)
	}
	external, err := s.changes(t.Context())
	if err != nil || external == local {
		t.Fatalf("external commit not observed: %v -> %v (%v)", local, external, err)
	}
}
