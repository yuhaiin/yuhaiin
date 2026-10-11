// Package supervisor runs multiple veepin servers in one process, mirroring the
// `veepin serve <proto>` command for each. The bare command constructs exactly
// one client.Server and blocks on it; the supervisor keeps a set of them,
// tracks their state, and rebuilds one without disturbing the others when its
// configuration changes.
//
// State lives as one JSON file per listener under a config directory the
// operator points it at. Each file is parsed into a ListenerConfig, which is
// the unit of change: applying the directory reconciles the live set to what
// the files say. A change is a cold rebuild -- the Server the veepin Server
// interface models is constructed-upfront, so reconfiguration is Close plus
// NewServer plus ListenAndServe again, scoped to the one listener that moved.
// Other listeners' goroutines are not touched.
//
// Everything that mutates host state (TUN address, forwarding, NAT) is owned by
// internal/hostnet and called through here; the supervisor matches the
// `NewServer installs no host state, the caller owns host networking` contract
// by being the caller.
package supervisor

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/confstore"
)

// ValidName reports whether name is one the supervisor could have written. The
// grammar lives in confstore, which owns everything that becomes a filename;
// this is re-exported so the management API's path handlers can check a routed
// name before joining it into a path rather than trusting the router.
func ValidName(name string) bool { return confstore.ValidName(name) }

// store is the on-disk listener directory. Everything file-shaped -- the strict
// decode, the duplicate-name check, the atomic write -- lives in confstore; the
// functions below are the supervisor's names for those operations.
var store = func(dir string) *confstore.Store[ListenerConfig] {
	return confstore.New(dir, "supervisor", NewListenerConfig)
}

// ListenerConfig is one server, the on-disk form of one JSON file in the config
// directory. It mirrors what `veepin serve <protocol>` reads from its flags:
// Options is the same map[string]string the protocol's ServerParseFunc takes,
// and SetupNAT / WAN carry the host-networking side exactly the bare command's
// `-setup-nat` / `-wan` flags do.
type ListenerConfig struct {
	// Name is the listener's identifier and the iptables comment tag.
	Name string `json:"name"`
	// Protocol is the registry name the listener runs, e.g. "wireguard".
	Protocol string `json:"protocol"`
	// Options is the protocol's options map. Each protocol's Opt* consts are the
	// keys; the values are whatever the bare command's flags accept.
	Options map[string]string `json:"options,omitempty"`
	// SetupNAT true means the supervisor configures interface address and
	// installs tagged iptables rules via internal/hostnet, the same path as
	// `veepin serve -setup-nat`. False means the operator manages the host
	// side themselves.
	SetupNAT bool `json:"setup_nat,omitempty"`
	// WAN is the upstream interface for NAT, passed to hostnet.
	WAN string `json:"wan,omitempty"`
	// Hostnames are the names and addresses clients will dial this listener by.
	// They become the SANs of any certificate the management plane generates
	// for it, and nothing else reads them -- a listener whose certificate the
	// operator supplied can leave this empty.
	//
	// Empty means keygen.DefaultHostnames: loopback plus the listener's own
	// name, which is enough for a laptop and not enough for a public gateway.
	// It has to be said somewhere, because the supervisor cannot know its own
	// public name, and a certificate that omits it is one no client accepts.
	Hostnames []string `json:"hostnames,omitempty"`
	// Enabled false means parse it, list it, but do not start it. Lets a
	// config disable a listener without deleting the file.
	//
	// It defaults to TRUE for a file that does not mention it -- see
	// NewListenerConfig and parseListenerBytes. A zero-value Go bool would
	// default the other way, which meant the obvious minimal config
	//
	//	{"name": "site-a", "protocol": "wireguard", "options": {...}}
	//
	// parsed, validated, listed, and never started, with no error and no log
	// line. No omitempty either: the field must survive a write-back, or
	// disabling a listener would drop the key and read back as enabled.
	Enabled bool `json:"enabled"`
}

// NewListenerConfig returns a ListenerConfig with the defaults a hand-written
// file gets when it stays silent. Callers that decode into a fresh config --
// the management API's create endpoint, and parseListenerBytes -- start from
// this rather than from the zero value, because encoding/json only writes the
// fields a document actually carries and so leaves these standing.
func NewListenerConfig() ListenerConfig {
	return ListenerConfig{Enabled: true}
}

// ConfigName is the listener's name, which is also its filename stem. It is what
// makes ListenerConfig a confstore.Named.
func (c ListenerConfig) ConfigName() string { return c.Name }

// Validate checks that a ListenerConfig is internally consistent. It does not
// check whether the protocol is known to the registry -- that requires a
// registry pointer and is enforced at build time, so the parse remains a pure
// data check that runs in the fuzz target without touching registration.
func (c ListenerConfig) Validate() error {
	if !confstore.ValidName(c.Name) {
		return fmt.Errorf("supervisor: name %q: %s", c.Name, confstore.NameRefusal(c.Name))
	}
	if c.Protocol == "" {
		return errors.New("supervisor: protocol is required")
	}
	if strings.ContainsAny(c.Name, "/\\") {
		// Belt-and-braces: the grammar already forbids "/" so this never fires;
		// it stays to make the safety intent explicit to a reader who skims the
		// regex as "looks permissive".
		return fmt.Errorf("supervisor: name %q must not contain a path separator", c.Name)
	}
	return nil
}

// ParseListenerFile reads and validates one JSON config file. It exists as a
// named function so it is the one obvious fuzz target.
func ParseListenerFile(path string) (ListenerConfig, error) {
	return store(filepath.Dir(path)).ParseFile(path)
}

// parseListenerBytes is the core FuzzParseListenerFile runs; it does no I/O so
// the fuzzer does not touch the disk.
func parseListenerBytes(body []byte) (ListenerConfig, error) {
	return store("").ParseBytes(body)
}

// LoadDir reads every *.json file under dir as a listener config, returning the
// set keyed by listener name. Directory evolution is handled by Apply, which
// reconciles to whatever LoadDir reports, so this is the read side only.
func LoadDir(dir string) (map[string]ListenerConfig, error) {
	return store(dir).LoadDir()
}

// WriteListenerFile writes a listener config to dir/<name>.json atomically. It
// is the management API's persistence path.
func WriteListenerFile(dir string, c ListenerConfig) error {
	return store(dir).Write(c)
}

// DeleteListenerFile removes a listener config by name.
func DeleteListenerFile(dir, name string) error {
	return store(dir).Delete(name)
}

// ListenerPath is the file a named listener's config lives at, for callers that
// stat or read it directly rather than going through the parse.
func ListenerPath(dir, name string) string {
	return store(dir).Path(name)
}

// KnownProtocol reports whether the registry recognises protocol as a server.
// It is a separate function from Validate so the parser stays pure-data and the
// registry check is applied at apply time, where a registration side-effect of
// an imported facade is the only thing that could know.
func KnownProtocol(protocol string) bool {
	return slices.Contains(client.AllServerProtocols(), protocol)
}
