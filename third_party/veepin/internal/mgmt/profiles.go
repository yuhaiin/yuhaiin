package mgmt

// The /api/profiles endpoints: client connection profiles stored under the
// supervisor's -profiles directory. They are the client-side analogue of the
// listener set — one confstore JSON file per profile, the same strict decode,
// the same name grammar, the same atomic mode-0600 write — exposed over the
// same HTTP surface so the panel can render, validate and edit them from the
// client protocols' OptSpec metadata.
//
// Unlike listeners, a profile is not a running thing: there is no state, no
// restart, no peers. The endpoints are pure CRUD over the store, and they are
// only mounted when the supervisor configured a profile directory (the panel's
// "profiles" tab then appears alongside "listeners").

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"slices"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/confstore"
	"github.com/xen0bit/veepin/internal/profile"
)

// profileStore is the on-disk profile directory the endpoints read and write.
func (s *Server) profileStore() *confstore.Store[profile.Config] {
	return confstore.New[profile.Config](s.profiles, "profile", nil)
}

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	cfgs, err := s.profileStore().LoadDir()
	if err != nil {
		// A profile directory that does not exist yet is an empty fleet, not a
		// fault. The supervisor defaults -profiles to <config>/profiles and
		// nothing creates it, so a fresh install otherwise answered 500 here --
		// which the dashboard re-polls every five seconds, forever.
		if errors.Is(err, fs.ErrNotExist) {
			writeJSON(w, http.StatusOK, map[string]any{"profiles": []profile.Config{}})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]profile.Config, 0, len(cfgs))
	for _, c := range cfgs {
		c.Options = redactClientOptions(c.Protocol, c.Options)
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	cfg, err := profile.ParseFile(profile.Path(s.profiles, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "no such profile", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.Options = redactClientOptions(cfg.Protocol, cfg.Options)
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	// Body first, then the lock: see handleCreateListener.
	var cfg profile.Config
	if err := decodeJSON(r, &cfg); err != nil {
		s.audit.record("profile.create", "", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mutate.Lock()
	defer s.mutate.Unlock()
	var res error
	name := cfg.Name
	defer func() { s.audit.record("profile.create", name, res) }()
	if err := cfg.Validate(); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !knownClientProtocol(cfg.Protocol) {
		res = fmt.Errorf("mgmt: unknown protocol %q", cfg.Protocol)
		http.Error(w, "unknown protocol", http.StatusBadRequest)
		return
	}
	// Run the protocol's own parse over the options, exactly as `veepin profile
	// add` does. Config.Validate above checks only the envelope -- a name and a
	// known protocol -- so without this the panel happily saved
	// {"protocol":"wireguard","options":{}} with a 201, and the operator found
	// out at `veepin connect` that private-key was required. That is the gap
	// client.ValidateOptions exists to close, and the panel is the consumer the
	// OptSpec tables were written for.
	if err := client.ValidateOptions(cfg.Protocol, cfg.Options); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// POST creates; a repeated create is a conflict, mirroring the listener
	// endpoint's stance.
	if _, err := os.Stat(profile.Path(s.profiles, cfg.Name)); err == nil {
		res = fmt.Errorf("mgmt: profile %q already exists", cfg.Name)
		http.Error(w, "a profile with that name already exists; PATCH it to edit",
			http.StatusConflict)
		return
	} else if !errors.Is(err, fs.ErrNotExist) {
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.profileStore().Write(cfg); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.Options = redactClientOptions(cfg.Protocol, cfg.Options)
	writeJSON(w, http.StatusCreated, cfg)
}

// profilePatch is the presence-aware PATCH view of a profile: pointers
// distinguish an omitted field from an explicit zero, exactly as listenerPatch
// does for listeners.
type profilePatch struct {
	Name     *string            `json:"name,omitempty"`
	Protocol *string            `json:"protocol,omitempty"`
	Options  *map[string]string `json:"options,omitempty"`
}

func (p profilePatch) applyTo(existing profile.Config) profile.Config {
	out := existing
	if p.Name != nil {
		out.Name = *p.Name
	}
	if p.Protocol != nil {
		out.Protocol = *p.Protocol
	}
	if p.Options != nil {
		out.Options = mergeOptions(existing.Options, *p.Options)
	}
	// Same reasoning as listenerPatch.applyTo: redaction resolves against the
	// current protocol, so carrying the old protocol's keys across a protocol
	// change would move a stored secret out of the redaction set.
	if p.Protocol != nil && *p.Protocol != existing.Protocol {
		out.Options = keepDeclaredClientOptions(out.Protocol, out.Options)
	}
	return out
}

// keepDeclaredClientOptions is keepDeclaredOptions against the client registry.
func keepDeclaredClientOptions(protocol string, opts map[string]string) map[string]string {
	specs, ok := client.ClientOptsFor(protocol)
	if !ok || opts == nil {
		return opts
	}
	declared := make(map[string]bool, len(specs))
	for _, sp := range specs {
		declared[sp.Key] = true
	}
	out := make(map[string]string, len(opts))
	for k, v := range opts {
		if declared[k] {
			out[k] = v
		}
	}
	return out
}

func (s *Server) handlePatchProfile(w http.ResponseWriter, r *http.Request) {
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	// Body first, then the lock: see handleCreateListener.
	var in profilePatch
	if err := decodeJSON(r, &in); err != nil {
		s.audit.record("profile.patch", name, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mutate.Lock()
	defer s.mutate.Unlock()
	var res error
	defer func() { s.audit.record("profile.patch", name, res) }()
	existing, err := profile.ParseFile(profile.Path(s.profiles, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			res = err
			http.Error(w, "no such profile", http.StatusNotFound)
			return
		}
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if in.Name != nil && *in.Name != name {
		res = errors.New("mgmt: rename refused")
		http.Error(w, "renaming a profile is not supported: create the new one and delete the old",
			http.StatusBadRequest)
		return
	}
	merged := in.applyTo(existing)
	if err := merged.Validate(); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !knownClientProtocol(merged.Protocol) {
		res = fmt.Errorf("mgmt: unknown protocol %q", merged.Protocol)
		http.Error(w, "unknown protocol", http.StatusBadRequest)
		return
	}
	if err := client.ValidateOptions(merged.Protocol, merged.Options); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.profileStore().Write(merged); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	merged.Options = redactClientOptions(merged.Protocol, merged.Options)
	writeJSON(w, http.StatusOK, merged)
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	s.mutate.Lock()
	defer s.mutate.Unlock()
	var res error
	defer func() { s.audit.record("profile.delete", name, res) }()
	if err := s.profileStore().Delete(name); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			res = err
			http.Error(w, "no such profile", http.StatusNotFound)
			return
		}
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

// knownClientProtocol reports whether the registry recognises protocol as a
// dialable client protocol.
func knownClientProtocol(protocol string) bool {
	return slices.Contains(client.AllProtocols(), protocol)
}

// redactClientOptions is redactOptions for the client side: it hides the values
// of the keys a protocol's client OptSpec marks secret. A protocol without a
// declaration is returned unchanged.
func redactClientOptions(protocol string, opts map[string]string) map[string]string {
	specs, _ := client.ClientOptsFor(protocol)
	return client.Redact(specs, opts)
}
