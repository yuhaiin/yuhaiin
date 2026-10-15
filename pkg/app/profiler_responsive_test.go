package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProfilerResponsiveWriter(t *testing.T) {
	html := "<!doctype html><html><head><title>pprof</title></head><body>Hello</body></html>"
	w := httptest.NewRecorder()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	n, err := (profilerResponsiveWriter{ResponseWriter: w}).Write([]byte(html))
	if err != nil || n != len(html) {
		t.Fatalf("Write returned %d, %v", n, err)
	}
	body := w.Body.String()
	if !strings.Contains(body, "name=\"viewport\"") ||
		!strings.Contains(body, "id=\"yuhaiin-pprof-responsive\"") {
		t.Fatal("responsive viewport or stylesheet missing")
	}
	if strings.Index(body, "id=\"yuhaiin-pprof-responsive\"") > strings.Index(body, "</head>") {
		t.Fatal("responsive CSS rendered outside head")
	}
	if !strings.Contains(body, "<body>Hello</body>") {
		t.Fatal("replaced original HTML content")
	}
}

func TestProfilerResponsiveWriterLeavesOtherContentUnchanged(t *testing.T) {
	for _, contentType := range []string{"text/plain", "application/vnd.google.protobuf+gzip", "text/vnd.graphviz"} {
		t.Run(contentType, func(t *testing.T) {
			body := []byte("<head>not an HTML response</head>")
			w := httptest.NewRecorder()
			w.Header().Set("Content-Type", contentType)
			n, err := (profilerResponsiveWriter{ResponseWriter: w}).Write(body)
			if err != nil || n != len(body) {
				t.Fatalf("Write returned %d, %v", n, err)
			}
			if got := w.Body.String(); got != string(body) {
				t.Fatalf("non-HTML content mutated: %q", got)
			}
		})
	}
}

func TestProfilerOfficialViewerHasMobileViewport(t *testing.T) {
	t.Setenv("DISABLED_PPROF", "")
	setPprofEnabled(true)
	t.Cleanup(func() { setPprofEnabled(false) })
	p := newProfilerService()
	t.Cleanup(p.stop)

	info, status, err := p.start("heap", 0)
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("start: %d %v", status, err)
	}
	_, done := waitForProfile(t, p, info.ID)
	if done.Status != "completed" {
		t.Fatalf("capture failed: %s", done.Status)
	}
	for _, suffix := range []string{"flamegraph", "top", "peek"} {
		t.Run(suffix, func(t *testing.T) {
			path := "/debug/profiler/" + info.ID + "/" + suffix
			w := httptest.NewRecorder()
			p.serveView(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("status: %d, %.200s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "name=\"viewport\"") ||
				!strings.Contains(w.Body.String(), "id=\"yuhaiin-pprof-responsive\"") {
				t.Fatal("mobile viewport/style not included in official pprof page")
			}
			if strings.Count(w.Body.String(), "name=\"viewport\"") != 1 {
				t.Fatal("viewport meta tag duplicated")
			}
		})
	}
}
