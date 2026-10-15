package app

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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

// prepareProfilerViewerConfigDir runs when the profiler is registered, never
// while serving a request. google/pprof's Web UI calls os.UserConfigDir even
// when saved UI configurations are unused. Android services and minimal
// containers may run without HOME, causing initialization to fail.
//
// When the platform has no user config directory, point XDG_CONFIG_HOME at a
// private directory under yuhaiin's existing data directory. This is a
// process-wide fallback because google/pprof has no public setting for the
// config path. Never replace a working user configuration or caller-provided
// XDG_CONFIG_HOME, and never set HOME.
func prepareProfilerViewerConfigDir(dataDir string) error {
	profilerViewerInitMu.Lock()
	defer profilerViewerInitMu.Unlock()

	_, lookupErr := os.UserConfigDir()
	if lookupErr == nil {
		return nil
	}
	if os.Getenv("XDG_CONFIG_HOME") != "" {
		return fmt.Errorf("pprof viewer user config directory: %w", lookupErr)
	}
	if dataDir == "" {
		return fmt.Errorf("pprof viewer needs a data directory without HOME: %w", lookupErr)
	}

	dir, err := filepath.Abs(filepath.Join(dataDir, "pprof-config"))
	if err != nil {
		return fmt.Errorf("resolve pprof viewer config directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create pprof viewer config directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("protect pprof viewer config directory: %w", err)
	}
	if err := os.Setenv("XDG_CONFIG_HOME", dir); err != nil {
		return fmt.Errorf("set pprof viewer config directory: %w", err)
	}
	if _, err := os.UserConfigDir(); err != nil {
		return fmt.Errorf("pprof viewer still cannot resolve config directory: %w", err)
	}
	return nil
}

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
func (profilerViewerUI) Print(...any)                        {}
func (profilerViewerUI) PrintErr(...any)                     {}
func (profilerViewerUI) IsTerminal() bool                    { return false }
func (profilerViewerUI) WantBrowser() bool                   { return false }
func (profilerViewerUI) SetAutoComplete(func(string) string) {}
