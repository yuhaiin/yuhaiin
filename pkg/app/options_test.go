package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestPprofCPUProfileStartsOnRequest(t *testing.T) {
	t.Setenv("DISABLED_PPROF", "")
	setPprofEnabled(false)
	t.Cleanup(func() { setPprofEnabled(false) })
	setPprofEnabled(true)
	mux := http.NewServeMux()
	RegisterHTTP(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/debug/pprof/profile?seconds=1", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	r, err := gzip.NewReader(bytes.NewReader(response.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	// Field 12 in the pprof Profile protobuf is the sample period (ns).
	// Startup sampling at 25 Hz prevents the standard HTTP collector from
	// selecting its 100 Hz rate and includes samples predating the request.
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 {
			t.Fatal("invalid profile field")
		}
		data = data[n:]
		switch key & 7 {
		case 0:
			v, n := binary.Uvarint(data)
			if n <= 0 {
				t.Fatal("invalid profile varint")
			}
			data = data[n:]
			if key>>3 == 12 {
				if v != 10_000_000 {
					t.Fatalf("CPU period = %d ns, want 100 Hz sampling on request", v)
				}
				return
			}
		case 2:
			v, n := binary.Uvarint(data)
			if n <= 0 || v > uint64(len(data)-n) {
				t.Fatal("invalid profile message")
			}
			data = data[n+int(v):]
		default:
			t.Fatalf("unexpected wire type %d", key&7)
		}
	}
	t.Fatal("missing CPU sample period")
}

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
