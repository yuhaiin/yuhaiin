package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	nativesqlite "github.com/yuhaiin/purego-sqlite"
)

func TestNativeEngineCapabilities(t *testing.T) {
	options, err := sqliteOptions()
	if err != nil {
		t.Fatal(err)
	}
	connector, err := nativesqlite.NewConnector(":memory:", options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SQLite %s, library %q", connector.Version(), connector.LibraryPath())
	for _, feature := range []string{"fts5", "json", "jsonb", "rtree"} {
		found, err := connector.HasFeature(feature)
		if err != nil || !found {
			t.Fatalf("required %s support: %v, %v", feature, found, err)
		}
	}
}

func TestNativeExecPragmaScript(t *testing.T) {
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	conn, err := store.DB().Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(t.Context(), "PRAGMA busy_timeout=5000; PRAGMA trusted_schema=OFF"); err != nil {
		t.Fatal(err)
	}
	for query, want := range map[string]int{"PRAGMA busy_timeout": 5000, "PRAGMA trusted_schema": 0} {
		var got int
		if err := conn.QueryRowContext(t.Context(), query).Scan(&got); err != nil || got != want {
			t.Fatalf("%s: got %d, want %d: %v", query, got, want, err)
		}
	}
}

func TestStorePoolReplacementPreservesPragmas(t *testing.T) {
	for _, kind := range []string{"configuration", "management"} {
		t.Run(kind, func(t *testing.T) {
			opener := Open
			if kind == "management" {
				opener = OpenManagement
			}
			store, err := opener(t.Context(), filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			// Recreate physical connections, as database/sql can after invalidation.
			store.DB().SetMaxIdleConns(0)
			if got := queryInt(t, store.DB(), "PRAGMA foreign_keys"); got != 1 {
				t.Fatalf("replacement connection lost foreign_keys: %d", got)
			}
			want := int64(sqliteExpectedSynchronous)
			if kind == "management" {
				want = 2
			}
			if got := queryInt(t, store.DB(), "PRAGMA synchronous"); got != want {
				t.Fatalf("replacement synchronous: %d, want %d", got, want)
			}
			if got := queryInt(t, store.DB(), "PRAGMA busy_timeout"); got != sqliteExpectedBusyTimeout {
				t.Fatalf("replacement busy timeout: %d", got)
			}
		})
	}
}

func TestNativeCancellationKeepsStoreUsable(t *testing.T) {
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	var sum int64
	err = store.DB().QueryRowContext(ctx, `WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT sum(x) FROM n`).Scan(&sum)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancel query: %v", err)
	}
	if _, err := store.DB().ExecContext(t.Context(), "INSERT INTO metadata(key,value) VALUES('after_cancel',?)", []byte{0, 1}); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, store.DB(), "PRAGMA foreign_keys"); got != 1 {
		t.Fatalf("foreign keys after cancellation: %d", got)
	}
}
