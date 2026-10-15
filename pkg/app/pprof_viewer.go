package app

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/google/pprof/driver"
	"github.com/google/pprof/profile"
)

// google/pprof does not expose an http.Handler constructor. Its public
// HTTPServer hook supplies the official handlers without opening a listener.
// Serialize initialization because the upstream driver uses process-wide
// defaults and settings. All viewer instances share identical defaults;
// per-request UI filters remain URL-scoped.
var profilerViewerInitMu sync.Mutex

type profilerView struct {
	once     sync.Once
	handlers map[string]http.Handler
	err      error
}

func (v *profilerView) handlersFor(raw []byte) (map[string]http.Handler, error) {
	v.once.Do(func() {
		profilerViewerInitMu.Lock()
		defer profilerViewerInitMu.Unlock()
		v.err = driver.PProf(&driver.Options{
			Flagset: &profilerViewerFlags{},
			UI:      profilerViewerUI{},
			Fetch:   profilerViewerFetch{raw: raw},
			HTTPServer: func(args *driver.HTTPServerArgs) error {
				v.handlers = args.Handlers
				return nil // Handlers outlive the driver call; no extra socket.
			},
		})
		if v.err == nil && len(v.handlers) == 0 {
			v.err = errors.New("pprof did not register viewer handlers")
		}
	})
	return v.handlers, v.err
}

type profilerViewerFetch struct{ raw []byte }

func (f profilerViewerFetch) Fetch(_ string, _, _ time.Duration) (*profile.Profile, string, error) {
	p, err := profile.ParseData(f.raw)
	return p, "yuhaiin-session.pb.gz", err
}

type profilerViewerFlags struct{ extra string }

func (f *profilerViewerFlags) Bool(_ string, value bool, _ string) *bool { return &value }
func (f *profilerViewerFlags) Int(_ string, value int, _ string) *int    { return &value }
func (f *profilerViewerFlags) Float64(_ string, value float64, _ string) *float64 {
	return &value
}
func (f *profilerViewerFlags) String(name, value, _ string) *string {
	if name == "http" {
		value = "127.0.0.1:1" // Only activates the HTTPServer callback.
	}
	return &value
}
func (f *profilerViewerFlags) StringList(_ string, value, _ string) *[]*string {
	if value == "" {
		v := make([]*string, 0)
		return &v
	}
	v := []*string{&value}
	return &v
}
func (f *profilerViewerFlags) ExtraUsage() string     { return f.extra }
func (f *profilerViewerFlags) AddExtraUsage(s string) { f.extra += s }
func (f *profilerViewerFlags) Parse(func()) []string  { return []string{"yuhaiin-session.pb.gz"} }

type profilerViewerUI struct{}

func (profilerViewerUI) ReadLine(string) (string, error) {
	return "", errors.New("interactive input disabled")
}
func (profilerViewerUI) Print(...interface{})                {}
func (profilerViewerUI) PrintErr(...interface{})             {}
func (profilerViewerUI) IsTerminal() bool                    { return false }
func (profilerViewerUI) WantBrowser() bool                   { return false }
func (profilerViewerUI) SetAutoComplete(func(string) string) {}
