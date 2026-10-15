package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"
)

func waitForProfile(t *testing.T, p *profilerService, id string) (*profilerSession, profilerSessionInfo) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		s, info, ok := p.get(id)
		if !ok {
			t.Fatal("session disappeared")
		}
		if info.Status != "running" {
			return s, info
		}
		select {
		case <-deadline:
			t.Fatal("profile collection timed out")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestProfilerSnapshotAndOfficialViewer(t *testing.T) {
	t.Setenv("DISABLED_PPROF", "")
	setPprofEnabled(true)
	t.Cleanup(func() { setPprofEnabled(false) })

	p := newProfilerService()
	t.Cleanup(p.stop)

	for _, kind := range []string{"heap", "allocs", "goroutine", "mutex", "block"} {
		t.Run(kind, func(t *testing.T) {
			info, status, err := p.start(kind, 0)
			if err != nil || status != http.StatusAccepted {
				t.Fatalf("start: %d %v", status, err)
			}
			s, done := waitForProfile(t, p, info.ID)
			if done.Status != "completed" {
				t.Fatalf("profile failed: %+v", done)
			}
			if _, err := profile.ParseData(s.raw); err != nil {
				t.Fatalf("bad profile: %v", err)
			}
		})
	}

	list := p.list()
	if len(list) != 5 {
		t.Fatalf("sessions = %d, want 5", len(list))
	}
	s, _, ok := p.get(list[0].ID)
	if !ok {
		t.Fatal("profile missing")
	}
	handlers, err := s.view.handlersFor(s.raw)
	if err != nil {
		t.Fatalf("start official pprof UI: %v", err)
	}
	for _, path := range []string{"/flamegraph", "/top", "/peek"} {
		handler := handlers[path]
		if handler == nil {
			t.Errorf("official viewer missing %s", path)
			continue
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s returned %d: %.200s", path, rec.Code, rec.Body.String())
		}
	}

	if !p.remove(list[0].ID) {
		t.Fatal("delete did not remove session")
	}
	if _, _, found := p.get(list[0].ID); found {
		t.Fatal("deleted session still accessible")
	}
}

func TestProfilerLimitsAndCancellation(t *testing.T) {
	t.Setenv("DISABLED_PPROF", "")
	setPprofEnabled(true)
	t.Cleanup(func() { setPprofEnabled(false) })

	p := newProfilerService()
	t.Cleanup(p.stop)

	for _, tc := range []struct {
		kind string
		seconds int
	}{
		{"goroutineleak", 0},
		{"cpu", 0},
		{"cpu", 121},
		{"heap", -1},
	} {
		if _, status, err := p.start(tc.kind, tc.seconds); err == nil || status != http.StatusBadRequest {
			t.Fatalf("expected invalid profile %q/%d, got %d %v", tc.kind, tc.seconds, status, err)
		}
	}
	active, status, err := p.start("cpu", 10)
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("cpu start: %d %v", status, err)
	}
	if _, status, err := p.start("cpu", 1); err == nil || status != http.StatusConflict {
		t.Fatalf("expected CPU conflict, got %d %v", status, err)
	}
	if !p.remove(active.ID) {
		t.Fatal("could not cancel CPU sampling")
	}
	deadline := time.After(3 * time.Second)
	for p.cpuRunning.Load() {
		select {
		case <-deadline:
			t.Fatal("CPU collector did not stop after cancellation")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	if pprofEnabled.Load() == false {
		t.Fatal("cancel should not disable pprof globally")
	}
	setPprofEnabled(false)
	if _, status, err := p.start("heap", 0); err == nil || status != http.StatusForbidden {
		t.Fatalf("disabled profile: %d %v", status, err)
	}
}

func TestProfilerViewerRequiresExistingCapability(t *testing.T) {
	p := newProfilerService()
	t.Cleanup(p.stop)
	setPprofEnabled(true)
	t.Cleanup(func() { setPprofEnabled(false) })

	for _, path := range []string{
		"/debug/profiler/missing/flamegraph",
		"/debug/profiler/" + strings.Repeat("a", 48) + "/flamegraph",
		"/debug/profiler/" + strings.Repeat("a", 48) + "/saveconfig",
	} {
		rec := httptest.NewRecorder()
		p.serveView(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d, want 404", path, rec.Code)
		}
	}
}
