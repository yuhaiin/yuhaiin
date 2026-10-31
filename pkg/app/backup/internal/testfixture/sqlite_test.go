package testfixture

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestDatabaseFixturesKeepIndependentDataAndPreserveExistingFiles(t *testing.T) {
	for _, fixture := range []struct {
		name string
		open openStore
	}{
		{"configuration", OpenState},
		{"management", OpenManagement},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "state.db")
			first, err := fixture.open(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = first.Close() })
			if _, err := first.DB().ExecContext(t.Context(), `INSERT INTO metadata(key,value) VALUES('fixture-marker','private')`); err != nil {
				t.Fatal(err)
			}
			if err := first.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := fixture.open(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			var value string
			if err := reopened.DB().QueryRowContext(t.Context(), `SELECT value FROM metadata WHERE key='fixture-marker'`).Scan(&value); err != nil || value != "private" {
				t.Fatal("reopening replaced existing fixture data", value, err)
			}
			second, err := fixture.open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = second.Close() })
			var count int
			if err := second.DB().QueryRowContext(t.Context(), `SELECT count(*) FROM metadata WHERE key='fixture-marker'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("fixture data leaked between databases", count, err)
			}
			if err := reopened.Close(); err != nil {
				t.Fatal(err)
			}
			wrongSchema := OpenState
			if fixture.name == "configuration" {
				wrongSchema = OpenManagement
			}
			if store, err := wrongSchema(t.Context(), path); err == nil {
				_ = store.Close()
				t.Fatal("existing file was replaced or accepted with the wrong schema")
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
				t.Fatalf("fixture permissions = %v, want 0600", info.Mode().Perm())
			}
		})
	}
}

func BenchmarkConfigurationDatabaseFixture(b *testing.B) {
	// Exclude the one migration performed per test process from the copy cost.
	warm, err := OpenState(b.Context(), filepath.Join(b.TempDir(), "warm.db"))
	if err != nil {
		b.Fatal(err)
	}
	if err := warm.Close(); err != nil {
		b.Fatal(err)
	}
	for _, fixture := range []struct {
		name string
		open openStore
	}{
		{"migrate", sqlite.Open},
		{"copy", OpenState},
	} {
		b.Run(fixture.name, func(b *testing.B) {
			directory := b.TempDir()
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				db, err := fixture.open(b.Context(), filepath.Join(directory, strconv.Itoa(i)+".db"))
				if err != nil {
					b.Fatal(err)
				}
				if err := db.Close(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
