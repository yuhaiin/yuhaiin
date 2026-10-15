package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	runtimepprof "runtime/pprof"
	"strings"
	"testing"
)

func profilerTestHeap(t *testing.T) []byte {
	t.Helper()
	var raw bytes.Buffer
	if err := runtimepprof.Lookup("heap").WriteTo(&raw, 0); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func TestProfilerDOTWithoutGraphviz(t *testing.T) {
	raw := profilerTestHeap(t)
	dot, err := profilerDOT(raw, nil)
	if err != nil {
		t.Fatalf("generate DOT: %v", err)
	}
	if !strings.Contains(dot, "digraph") {
		t.Fatalf("missing digraph header: %.120s", dot)
	}
	for _, query := range []url.Values{
		{"f": {"testing"}},
		{"n": {"10"}, "trim": {"true"}},
		{"si": {"inuse_space"}},
		{"focus": {"testing"}},
	} {
		if _, err := profilerDOT(raw, query); err != nil {
			t.Errorf("DOT options %v: %v", query, err)
		}
	}
	for _, query := range []url.Values{
		{"http": {"localhost:1234"}},
		{"output": {"/tmp/graph.dot"}},
		{"focus": {"a", "b"}},
		{"focus": {strings.Repeat("x", 1025)}},
		{"n": {"abc"}},
		{"f": {"a"}, "focus": {"b"}},
	} {
		if _, err := profilerDOT(raw, query); err == nil {
			t.Errorf("expected rejection for options %v", query)
		}
	}
}

func TestProfilerWASMGraphBridge(t *testing.T) {
	t.Setenv("DISABLED_PPROF", "")
	setPprofEnabled(true)
	t.Cleanup(func() { setPprofEnabled(false) })

	p := newProfilerService()
	t.Cleanup(p.stop)
	info, status, err := p.start("heap", 0)
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("start heap capture: %d %v", status, err)
	}
	_, result := waitForProfile(t, p, info.ID)
	if result.Status != "completed" {
		t.Fatalf("capture failed: %s", result.Status)
	}
	base := "/debug/profiler/" + info.ID
	for _, tc := range []struct {
		path     string
		wantCode int
		wantText string
	}{
		{base + "/dot", http.StatusOK, "digraph"},
		{base + "/dot?n=3", http.StatusOK, "digraph"},
		{base + "/dot?si=inuse_space", http.StatusOK, "digraph"},
		{base + "/dot?http=1", http.StatusBadRequest, "unknown graph option"},
		{base + "/graph?focus=Go", http.StatusOK, "yuhaiin:pprof-graph"},
	} {
		w := httptest.NewRecorder()
		p.serveView(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.wantCode || !strings.Contains(w.Body.String(), tc.wantText) {
			t.Errorf("%s: code=%d body=%.200s", tc.path, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: missing Cache-Control no-store", tc.path)
		}
	}

	// Using a different sample type in the DOT endpoint must not poison the
	// process-global currentConfig of the official pprof Viewer.
	for _, suffix := range []string{"flamegraph", "top", "peek"} {
		w := httptest.NewRecorder()
		p.serveView(w, httptest.NewRequest(http.MethodGet, base+"/"+suffix, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s after DOT: %d: %.200s", suffix, w.Code, w.Body.String())
		}
	}
}
