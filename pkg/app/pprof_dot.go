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

// Short keys are the URL parameter names used by the official pprof UI.
// The longer aliases are accepted for the independent React filter controls.
var profilerDOTParams = map[string]string{
	"f": "focus", "focus": "focus", "i": "ignore", "ignore": "ignore",
	"h": "hide", "hide": "hide", "s": "show", "show": "show",
	"sf": "show_from", "show_from": "show_from",
	"tf": "tagfocus", "tagfocus": "tagfocus", "ti": "tagignore", "tagignore": "tagignore",
	"ts": "tagshow", "tagshow": "tagshow", "th": "taghide", "taghide": "taghide",
	"si": "sample_index", "sample_index": "sample_index",
	"n": "nodecount", "nodecount": "nodecount",
	"nf": "nodefraction", "nodefraction": "nodefraction",
	"ef": "edgefraction", "edgefraction": "edgefraction",
	"g": "granularity", "granularity": "granularity",
	"rel": "relative_percentages", "relative_percentages": "relative_percentages",
	"trim": "trim", "mean": "mean", "noinlines": "noinlines",
	"unit": "unit",
}

// pprof's public driver stores the last command's configuration globally.
// Explicit defaults prevent one graph request from affecting a subsequent
// graph, and a second lightweight report restores official Viewer defaults.
func profilerDOTDefaults() url.Values {
	return url.Values{
		"sample_index": {""}, "nodecount": {"-1"},
		"nodefraction": {"0.005"}, "edgefraction": {"0.001"},
		"unit": {"minimum"}, "trim": {"true"}, "granularity": {""},
		"focus": {""}, "ignore": {""}, "hide": {""}, "show": {""},
		"show_from": {""}, "tagfocus": {""}, "tagignore": {""},
		"tagshow": {""}, "taghide": {""},
		"relative_percentages": {"false"}, "mean": {"false"},
		"noinlines": {"false"},
	}
}

func profilerDOT(raw []byte, query url.Values) (dot string, err error) {
	opts := profilerDOTDefaults()
	for name, values := range query {
		flag, ok := profilerDOTParams[name]
		if !ok {
			return "", fmt.Errorf("unknown graph option %q", name)
		}
		if len(values) != 1 || len(values[0]) > 1024 {
			return "", fmt.Errorf("invalid graph option %q", name)
		}
		if _, duplicated := query[flag]; duplicated && name != flag {
			return "", fmt.Errorf("duplicate graph option %q", flag)
		}
		switch flag {
		case "nodecount":
			if n, parseErr := strconv.Atoi(values[0]); parseErr != nil || n < 0 || n > 500 {
				return "", fmt.Errorf("invalid graph node count %q", values[0])
			}
		case "nodefraction", "edgefraction":
			if fraction, parseErr := strconv.ParseFloat(values[0], 64); parseErr != nil || fraction < 0 || fraction > 1 {
				return "", fmt.Errorf("invalid graph fraction %q", values[0])
			}
		case "trim", "mean", "noinlines", "relative_percentages":
			if _, parseErr := strconv.ParseBool(values[0]); parseErr != nil {
				return "", fmt.Errorf("invalid graph boolean %q", values[0])
			}
		}
		opts.Set(flag, values[0])
	}

	// Upstream pprof's currentConfig is global. Existing official handlers
	// must not observe filter or sample-type changes from a DOT request.
	profilerViewerInitMu.Lock()
	defer profilerViewerInitMu.Unlock()
	defer func() {
		var discard profilerDOTWriter
		restoreErr := driver.PProf(&driver.Options{
			Flagset: &profilerDOTFlags{options: profilerDOTDefaults(), command: "comments"},
			UI: profilerViewerUI{}, Fetch: profilerViewerFetch{raw: raw}, Writer: &discard,
		})
		if restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore pprof viewer configuration: %w", restoreErr))
		}
	}()

	var out profilerDOTWriter
	if reportErr := driver.PProf(&driver.Options{
		Flagset: &profilerDOTFlags{options: opts, command: "dot"},
		UI:      profilerViewerUI{},
		Fetch:   profilerViewerFetch{raw: raw},
		Writer:  &out,
	}); reportErr != nil {
		return "", fmt.Errorf("generate graph DOT: %w", reportErr)
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
	command string
}

func (f *profilerDOTFlags) Bool(name string, def bool, _ string) *bool {
	if name == f.command {
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
