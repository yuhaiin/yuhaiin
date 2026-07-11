package app

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

type testStateStore struct {
	db *sql.DB
}

func (s testStateStore) SQLDB(context.Context) (*sql.DB, error) { return s.db, nil }

func TestCompactStateStoreVacuum(t *testing.T) {
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.DB().ExecContext(ctx, `CREATE TABLE vacuum_test(data BLOB)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `INSERT INTO vacuum_test VALUES (zeroblob(1048576))`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `DELETE FROM vacuum_test`); err != nil {
		t.Fatal(err)
	}

	var freeBefore int
	if err := store.DB().QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&freeBefore); err != nil {
		t.Fatal(err)
	}
	if freeBefore == 0 {
		t.Fatal("expected deleted pages before vacuum")
	}

	if err := compactStateStore(ctx, testStateStore{db: store.DB()}); err != nil {
		t.Fatal(err)
	}

	var freeAfter int
	if err := store.DB().QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&freeAfter); err != nil {
		t.Fatal(err)
	}
	if freeAfter != 0 {
		t.Fatalf("freelist_count after vacuum = %d, want 0", freeAfter)
	}
}

func TestPprofHandlerHonorsRuntimeSetting(t *testing.T) {
	t.Setenv("DISABLED_PPROF", "")
	setPprofEnabled(false)
	t.Cleanup(func() { setPprofEnabled(false) })

	mux := http.NewServeMux()
	RegisterHTTP(mux)

	request := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled pprof status = %d, want %d", response.Code, http.StatusNotFound)
	}

	setPprofEnabled(true)
	response = httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("enabled pprof status = %d, want %d", response.Code, http.StatusOK)
	}
}
