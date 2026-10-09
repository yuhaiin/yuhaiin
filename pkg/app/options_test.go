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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"gvisor.dev/gvisor/pkg/sleep"
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
	ctx := t.Context()
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

func TestPprofRejectsGoroutineLeakProfile(t *testing.T) {
	t.Setenv("DISABLED_PPROF", "")
	setPprofEnabled(false)
	t.Cleanup(func() { setPprofEnabled(false) })
	mux := http.NewServeMux()
	RegisterHTTP(mux)

	request := httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutineleak", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled pprof status = %d, want 404", response.Code)
	}

	setPprofEnabled(true)
	for _, query := range []string{"", "?debug=1", "?debug=2", "?seconds=1"} {
		t.Run(query, func(t *testing.T) {
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutineleak"+query, nil))
			if response.Code != http.StatusNotImplemented {
				t.Fatalf("goroutineleak status = %d, want 501", response.Code)
			}
			if !bytes.Contains(response.Body.Bytes(), []byte("gVisor")) {
				t.Fatalf("missing compatibility explanation: %s", response.Body.String())
			}
		})
	}

	response = httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutine?debug=1", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("ordinary goroutine profile status = %d, want 200", response.Code)
	}
}

func TestPprofGoroutineLeakKeepsGvisorWorkerAlive(t *testing.T) {
	const helperEnv = "YUHAIIN_TEST_PPROF_GVISOR_WORKER"
	if os.Getenv(helperEnv) != "1" {
		// The unguarded handler marks this live worker as leaked. Its next
		// wake-up then throws a runtime fatal, which must stay in a subprocess.
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestPprofGoroutineLeakKeepsGvisorWorkerAlive$")
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("gVisor worker failed after profiling: %v\n%s", err, output)
		}
		return
	}

	t.Setenv("DISABLED_PPROF", "")
	setPprofEnabled(true)
	t.Cleanup(func() { setPprofEnabled(false) })
	var sleeper sleep.Sleeper
	var waker sleep.Waker
	sleeper.AddWaker(&waker)
	done := make(chan struct{})
	go func() {
		sleeper.Fetch(true)
		close(done)
	}()

	// Wait for the real custom park, rather than racing profiling against
	// goroutine startup. No normal channel wait can reproduce this bug.
	stack := make([]byte, 1<<20)
	deadline := time.Now().Add(3 * time.Second)
	for {
		n := runtime.Stack(stack, true)
		if strings.Contains(string(stack[:n]), "gvisor.dev/gvisor/pkg/sleep.(*Sleeper).nextWaker") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("gVisor worker did not park")
		}
		runtime.Gosched()
	}

	mux := http.NewServeMux()
	RegisterHTTP(mux)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutineleak?debug=2", nil))
	waker.Assert()
	select {
	case <-done:
		sleeper.Done()
	case <-time.After(time.Second):
		t.Fatal("gVisor worker did not wake after profiling")
	}
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("goroutineleak status = %d, want 501", response.Code)
	}
}
