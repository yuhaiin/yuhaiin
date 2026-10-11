// Package confstore is the one-JSON-file-per-entity directory that both the
// supervisor's listener set and the client's saved profiles are.
//
//	<dir>/site-a.json      one file per entity, named for the entity
//	<dir>/branch.json
//
// The two callers arrived at the same shape independently -- the same name
// grammar, the same strict decode, the same atomic write-and-rename, the same
// duplicate-name check -- and then carried it as two near-identical copies. This
// is that shape written once.
//
// What a caller supplies is the type, its name, and its validation:
//
//	type Config struct{ Name string; ... }
//	func (c Config) ConfigName() string { return c.Name }
//	func (c Config) Validate() error    { ... }
//
//	store := confstore.New[Config]("/etc/veepin", "supervisor", newConfig)
//
// # Why the name grammar lives here
//
// An entity's name is its filename, so it is the one field that reaches the
// filesystem. ValidName is the single definition of what may do that -- lower
// case, digits and hyphens, at most 32 octets -- and every read and write path
// checks it. It is also safe as an iptables `--comment` value, which the
// supervisor relies on: it tags every rule it installs `veepin:<name>` and
// deletes by the same tag, so a name that needed quoting would be a name the
// teardown could not match.
//
// # Durability
//
// Write is temp file, write, fsync, close, rename. The fsync is what makes the
// rename mean anything: without it a crash between the two can leave the new
// name pointing at a file whose contents never reached the disk, which for a
// listener config is a listener that will not parse on the next boot.
package confstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// nameRe is the entity-name grammar: a lower-case, digit, or hyphen identifier
// of 1-32 octets, starting with a letter or digit.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// reserved are the names an entity may not take because the config root already
// uses them for its own subdirectories: <dir>/mgmt holds the bearer token,
// <dir>/profiles holds the saved client profiles.
//
// The grammar admits both, and an entity's name is not only its filename but
// also the directory its generated key material goes in -- so a listener called
// "profiles" would generate PEMs into the profile directory, and deleting it
// would take every profile on the box with it. Refusing the two names here is
// what stops that, in the one place that already owns "what may become a path
// element". The cost is that neither word can name a listener or a profile,
// which is a trade an operator can work around and a data loss is not.
var reserved = map[string]bool{"mgmt": true, "profiles": true}

// ValidName reports whether name may be used as an entity name, and therefore
// as a path element. Callers validate with it rather than re-deriving the rule,
// so there is one answer to "what may become a filename here".
func ValidName(name string) bool { return nameRe.MatchString(name) && !reserved[name] }

// ReservedName reports whether name is refused because the config root claims
// it, rather than because it fails the grammar. Callers use it to say which of
// the two rules a name broke.
func ReservedName(name string) bool { return reserved[name] }

// NameGrammar is the human-readable form of the rule, for error messages.
func NameGrammar() string { return nameRe.String() }

// NameRefusal says which of the two rules a name broke, so the operator who
// picked "profiles" is not told to consult a regular expression that admits it.
// Callers phrasing their own "bad name" error use this for the reason clause.
func NameRefusal(name string) string {
	if reserved[name] {
		return "the config root uses that name for its own directory"
	}
	return "bad name, want " + NameGrammar()
}

// Named is what a stored type must be able to say about itself: what it is
// called, and whether it makes sense.
type Named interface {
	// ConfigName is the entity's identifier and the stem of its filename.
	ConfigName() string
	// Validate reports whether the entity is internally consistent. The store
	// calls it on every read and before every write, so a malformed entity
	// never reaches the disk and never leaves it unnoticed.
	Validate() error
}

// Store reads and writes entities of one type under one directory.
type Store[T Named] struct {
	dir string
	// prefix is the package name errors are tagged with, per house style
	// ("supervisor: ...", "profile: ...").
	prefix string
	// defaults returns the value a decode starts from, so a field a document
	// omits keeps its intended default rather than Go's zero value.
	defaults func() T
}

// New returns a Store over dir. prefix tags the errors; defaults supplies the
// starting value for each decode and may be nil, which means the zero value.
func New[T Named](dir, prefix string, defaults func() T) *Store[T] {
	if defaults == nil {
		defaults = func() T { var zero T; return zero }
	}
	return &Store[T]{dir: dir, prefix: prefix, defaults: defaults}
}

// Dir is the directory the store reads and writes.
func (s *Store[T]) Dir() string { return s.dir }

// ParseFile reads and validates one file by path.
func (s *Store[T]) ParseFile(path string) (T, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("%s: reading %s: %w", s.prefix, filepath.Base(path), err)
	}
	return s.ParseBytes(body)
}

// ParseBytes is the I/O-free core, which is what makes it the obvious fuzz
// target: a hand-edited or API-written file must produce an error rather than a
// panic, whatever is in it.
//
// Unknown fields are rejected. A key the type does not have is a typo or a
// config written for a different version, and silently ignoring it means an
// operator's setting does nothing while the file looks right.
func (s *Store[T]) ParseBytes(body []byte) (T, error) {
	c := s.defaults()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		var zero T
		return zero, fmt.Errorf("%s: parsing config: %w", s.prefix, err)
	}
	// Decode reads exactly one value and stops, so two concatenated documents
	// parse as the first one alone. An interrupted editor or a script that
	// appended instead of replacing produces exactly that, and the half the
	// operator can see is the half being ignored -- the same silent-drop failure
	// DisallowUnknownFields above exists to prevent.
	if dec.More() {
		var zero T
		return zero, fmt.Errorf("%s: trailing data after the config document", s.prefix)
	}
	if err := c.Validate(); err != nil {
		var zero T
		return zero, err
	}
	return c, nil
}

// LoadDir reads every *.json file in the directory, keyed by entity name.
//
// Two files naming the same entity is an error, not a merge: each name maps to
// exactly one entity, so a duplicate means one of the two files is being
// ignored and the operator cannot tell which. Subdirectories are skipped, which
// is what lets the supervisor keep its own state in <dir>/mgmt/.
func (s *Store[T]) LoadDir() (map[string]T, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("%s: reading config dir %q: %w", s.prefix, s.dir, err)
	}
	out := make(map[string]T, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		c, err := s.ParseFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			// ParseFile already names the file and prefixes the package; wrapping
			// again produced "supervisor: site-a.json: supervisor: reading
			// site-a.json: ...".
			return nil, err
		}
		name := c.ConfigName()
		// The filename is how the operator finds the entity and how Write will
		// name it; the name field is how everything else refers to it. When they
		// disagree, a hand-edited site-a.json saying "name":"site-b" loads as
		// site-b, the next Write creates site-b.json, and the load AFTER that
		// fails "duplicate name" -- taking the whole fleet down, since LoadDir
		// fails whole. Refuse at the first read, where the file is still the only
		// one and the message can say which.
		if stem := strings.TrimSuffix(e.Name(), ".json"); stem != name {
			return nil, fmt.Errorf("%s: %s: config names itself %q; rename the file or the field so they agree",
				s.prefix, e.Name(), name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%s: duplicate name %q (from %s)", s.prefix, name, e.Name())
		}
		out[name] = c
	}
	return out, nil
}

// Write stores c at <dir>/<name>.json atomically, mode 0600.
//
// 0600 because these files hold whatever the protocol needs: private keys,
// pre-shared keys, passphrases. That is the same filesystem-permission posture
// the protocol facades already rely on for PEM files and the IKEv2 EAP user
// list -- the secret is protected by the mode on the file, not by anything in
// the format.
func (s *Store[T]) Write(c T) error {
	if err := c.Validate(); err != nil {
		return err
	}
	name := c.ConfigName()
	// Validate above is the caller's rule; this is the store's. Nothing in the
	// Named interface obliges a Validate to check the name, and Write is the
	// function that turns it into a path -- so a type whose Validate forgot
	// would have this one create <dir>/../../etc/cron.d/x.json at 0600. Delete
	// makes the same check for the same reason.
	if !ValidName(name) {
		return fmt.Errorf("%s: refusing to write %q: %s", s.prefix, name, NameRefusal(name))
	}
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: marshalling %q: %w", s.prefix, name, err)
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("%s: creating config dir %q: %w", s.prefix, s.dir, err)
	}
	final := filepath.Join(s.dir, name+".json")
	// Unique temp name via os.CreateTemp, not a fixed final+".tmp". Two
	// concurrent Write calls for the SAME entity would otherwise share one temp
	// path: each truncates and writes the other's in-flight content, and the
	// two renames race -- the second rename can install a torn file, or the
	// first can succeed and be silently overwritten by the other's copy. A
	// random suffix makes each writer's temp distinct, so at worst the two
	// renames serialize and the last one wins whole.
	f, err := os.CreateTemp(s.dir, name+".tmp.*")
	if err != nil {
		return fmt.Errorf("%s: creating temp file: %w", s.prefix, err)
	}
	// No Chmod: os.CreateTemp already creates at 0600, which is the mode this
	// file must end up with.
	tmp := f.Name()
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: writing %q: %w", s.prefix, name, err)
	}
	// Before the rename, not after: the rename is only atomic with respect to
	// the name, and a crash between the two would otherwise leave the final
	// name pointing at a file whose contents never reached the disk.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: syncing %q: %w", s.prefix, name, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: closing temp file: %w", s.prefix, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: installing %q: %w", s.prefix, name, err)
	}
	return nil
}

// Delete removes an entity's file. The name is checked first: it is about to
// become a path element, and this is the last place that can refuse one that
// should never have got this far.
func (s *Store[T]) Delete(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("%s: refusing to delete %q: %s", s.prefix, name, NameRefusal(name))
	}
	if err := os.Remove(filepath.Join(s.dir, name+".json")); err != nil {
		return fmt.Errorf("%s: deleting %q: %w", s.prefix, name, err)
	}
	return nil
}

// Path is the file an entity of the given name lives at. Callers that need to
// stat or read the file directly use this rather than rebuilding the join.
func (s *Store[T]) Path(name string) string {
	return filepath.Join(s.dir, name+".json")
}
