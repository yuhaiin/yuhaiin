package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverySnapshotBudgetCancellationAndAliasOwnership(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "state.db")
	store, err := Open(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	alias := filepath.Join(directory, "alias.db")
	if err := os.Link(source, alias); err == nil {
		if err := RequireClosed(alias); err == nil {
			t.Fatal("physical alias hid the active database owner")
		}
	}
	destination := filepath.Join(directory, "snapshot.db")
	if _, err := SnapshotRecoveryDatabase(t.Context(), source, destination, "configuration", 1); err == nil {
		t.Fatal("size budget was ignored")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := SnapshotRecoveryDatabase(ctx, source, destination, "configuration", 100<<30); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled snapshot returned %v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed snapshot published a partial database")
	}
}

func TestRecoveryReadOnlySnapshotIncludesWALAndDoesNotMigrate(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "state.db")
	store, err := Open(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.DB().ExecContext(t.Context(), "INSERT INTO metadata(key,value) VALUES('wal_recovery_source','committed')"); err != nil {
		t.Fatal(err)
	}
	if err := RequireClosed(source); err == nil {
		t.Fatal("live store was considered stopped")
	}
	destination := filepath.Join(directory, "snapshot.db")
	version, err := SnapshotRecoveryDatabase(t.Context(), source, destination, "configuration", 100<<30)
	if err != nil || version != 23 {
		t.Fatalf("read-only WAL snapshot: %d %v", version, err)
	}
	reader, err := OpenSnapshotReader(t.Context(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var value string
	if err := reader.QueryRowContext(t.Context(), "SELECT value FROM metadata WHERE key='wal_recovery_source'").Scan(&value); err != nil || value != "committed" {
		t.Fatal("committed WAL data was lost")
	}
	if _, err := reader.ExecContext(t.Context(), "DELETE FROM metadata"); err == nil {
		t.Fatal("snapshot reader was writable")
	}
	if _, err := SnapshotRecoveryDatabase(t.Context(), source, destination, "configuration", 100<<30); err == nil {
		t.Fatal("snapshot replaced an existing destination")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RequireClosed(source); err != nil {
		t.Fatal(err)
	}
	id, err := RecoveryInstanceID(t.Context(), source, true)
	if err != nil {
		t.Fatal(err)
	}
	again, err := RecoveryInstanceID(t.Context(), source, true)
	if err != nil || again != id {
		t.Fatal("instance identifier changed")
	}
	if err := BindRecoveryInstance(t.Context(), destination, id); err != nil {
		t.Fatal(err)
	}
	bound, err := RecoveryInstanceID(t.Context(), destination, false)
	if err != nil || bound != id {
		t.Fatal("snapshot binding missing")
	}
	if _, err := os.Stat(destination + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("snapshot identity binding left WAL")
	}
}
