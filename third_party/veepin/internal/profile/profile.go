// Package profile saves named client connection configurations under
// $XDG_CONFIG_HOME/veepin/profiles/ (default ~/.config/veepin/profiles/), one
// JSON file per profile.
//
// It is the client-side analogue of the supervisor's listener directory, and
// literally so: both are internal/confstore stores over the same
// name-plus-protocol-plus-options shape, so the strict decode, the name
// grammar, the duplicate check, and the atomic write are one implementation
// rather than two copies that agree today.
//
// A profile is the unit the command resolves:
//
//	veepin connect home   # looks up ~/.config/veepin/profiles/home.json
//
// The lookup is tried after the registry: if "home" is not a known protocol
// name, the command checks the profiles directory. Profiles are additive to the
// bare `veepin connect <protocol> -flag ...` path; both use the same Dial.
package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xen0bit/veepin/internal/confstore"
)

// DefaultDir returns the profiles directory under the user's config home.
// XDG_CONFIG_HOME is consulted via os.UserConfigDir; if that fails (no $HOME),
// the caller (the command) supplies an explicit path.
func DefaultDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "veepin", "profiles"), nil
}

// store is the on-disk profile directory. Unlike a listener config there is no
// field with a non-zero default, so the store decodes from the zero value.
func store(dir string) *confstore.Store[Config] {
	return confstore.New[Config](dir, "profile", nil)
}

// Config is a single named client connection.
type Config struct {
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Options  map[string]string `json:"options,omitempty"`
}

// ConfigName is the profile's name, which is also its filename stem. It is what
// makes Config a confstore.Named.
func (c Config) ConfigName() string { return c.Name }

// Validate checks the profile's fields.
func (c Config) Validate() error {
	if !confstore.ValidName(c.Name) {
		return fmt.Errorf("profile: name %q: %s", c.Name, confstore.NameRefusal(c.Name))
	}
	if c.Protocol == "" {
		return errors.New("profile: protocol is required")
	}
	return nil
}

// LoadDir reads every *.json file under dir as a profile, keyed by name.
func LoadDir(dir string) (map[string]Config, error) {
	return store(dir).LoadDir()
}

// ParseFile reads a profile JSON file from disk.
func ParseFile(path string) (Config, error) {
	return store(filepath.Dir(path)).ParseFile(path)
}

// ParseBytes is the I/O-free core: it parses and validates a profile document
// without touching the disk, so the CLI's `profile add` reads stdin through the
// same code path the on-disk reader uses.
func ParseBytes(body []byte) (Config, error) {
	return store("").ParseBytes(body)
}

// Write stores a profile atomically at dir/<name>.json, mode 0600 so secrets in
// the options map are protected the same way listener config files are.
func Write(dir string, c Config) error {
	return store(dir).Write(c)
}

// Delete removes a profile by name from dir.
func Delete(dir, name string) error {
	return store(dir).Delete(name)
}

// Path is the file a named profile lives at.
func Path(dir, name string) string {
	return store(dir).Path(name)
}
