package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"

	"github.com/google/pprof/driver"
)

// The official pprof Graph handler invokes an external Graphviz process.
// Instead, ask pprof's public driver to emit its DOT report directly into a
// bounded in-memory Writer. That keeps graph semantics owned by upstream
// pprof; the browser performs only DOT -> SVG layout with Graphviz WASM.
const profilerMaxDOT = 4 << 20

var profilerDOTParams = map[string]bool{
	"focus": true, "ignore": true, "hide": true, "show": true,
	"show_from": true, "tagfocus": true, "tagignore": true,
	"tagshow": true, "taghide": true, "sample_index": true,
	"nodecount": true, "nodefraction": true, "edgefraction": true,
	"unit": true, "granularity": true, "relative_percentages": true,
	"trim": true, "mean": true, "noinlines": true,
}

func profilerDOT(raw []byte, query url.Values) (string, error) {
	for name, values := range query {
		if !profilerDOTParams[name] {
			return "", fmt.Errorf("unknown graph option %q", name)
		}
		if len(values) != 1 || len(values[0]) > 1024 {
			return "", fmt.Errorf("invalid graph option %q", name)
		}
	}
	var out profilerDOTWriter
	// The pprof driver uses global default settings. Serialize with its
	// per-session initialization to avoid concurrent command-line report runs.
	profilerViewerInitMu.Lock()
	defer profilerViewerInitMu.Unlock()
	err := driver.PProf(&driver.Options{
		Flagset: &profilerDOTFlags{options: query},
		UI:      profilerViewerUI{},
		Fetch:   profilerViewerFetch{raw: raw},
		Writer:  &out,
	})
	if err != nil {
		return "", fmt.Errorf("generate graph DOT: %w", err)
	}
	if out.Len() == 0 {
		return "", errors.New("pprof returned an empty DOT graph")
	}
	return out.String(), nil
}

type profilerDOTWriter struct{ bytes.Buffer }

func (w *profilerDOTWriter) Open(name string) (io.WriteCloser, error) {
	if name != "yuhaiin-graph.dot" {
		return nil, fmt.Errorf("unexpected pprof output %q", name)
	}
	w.Reset()
	return profilerDOTOutput{w}, nil
}

type profilerDOTOutput struct{ writer *profilerDOTWriter }

func (w profilerDOTOutput) Write(p []byte) (int, error) {
	if len(p) > profilerMaxDOT-w.writer.Len() {
		return 0, errors.New("pprof DOT graph exceeds 4 MiB")
	}
	return w.writer.Write(p)
}
func (profilerDOTOutput) Close() error { return nil }

type profilerDOTFlags struct {
	profilerViewerFlags
	options url.Values
}

func (f *profilerDOTFlags) Bool(name string, def bool, _ string) *bool {
	if name == "dot" {
		return new(true)
	}
	if value, ok := f.options[name]; ok {
		parsed, err := strconv.ParseBool(value[0])
		if err == nil {
			return new(parsed)
		}
	}
	return new(def)
}
func (f *profilerDOTFlags) Int(name string, def int, _ string) *int {
	if value, ok := f.options[name]; ok {
		if parsed, err := strconv.Atoi(value[0]); err == nil {
			return &parsed
		}
	}
	return &def
}
func (f *profilerDOTFlags) Float64(name string, def float64, _ string) *float64 {
	if value, ok := f.options[name]; ok {
		if parsed, err := strconv.ParseFloat(value[0], 64); err == nil {
			return &parsed
		}
	}
	return &def
}
func (f *profilerDOTFlags) String(name, def, _ string) *string {
	if name == "output" {
		out := "yuhaiin-graph.dot"
		return &out
	}
	if value, ok := f.options[name]; ok {
		return &value[0]
	}
	return &def
}
func (f *profilerDOTFlags) Parse(func()) []string {
	return []string{"yuhaiin-session.pb.gz"}
}

// graphBridgePage is static: never interpolate a profile name or a session ID.
// The parent checks both the iframe source window and origin before accepting
// the message, and already knows the selected session capability.
const graphBridgePage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>pprof Graph</title></head>
<body><p>Opening Graphviz WASM graph…</p><script>
window.parent.postMessage({type:"yuhaiin:pprof-graph",query:window.location.search},"*");
</script></body></html>`

func validProfilerGraphQuery(raw string) bool {
	return len(raw) <= 4096
}
