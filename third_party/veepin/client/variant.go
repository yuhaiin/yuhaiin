// Protocol variants: a second registry name for an existing protocol under
// which some policy is mandatory rather than negotiated.
//
// The whole scheme exists because of one asymmetry. A policy expressed as a
// flag is a modifier an operator can forget, and forgetting it yields the
// weaker behaviour silently -- the handshake still succeeds, just with less
// protection. A policy expressed as a NAME cannot be forgotten: `veepin serve
// pq-ikev2` either starts with the guarantee in force or does not start.
//
// The second reason is evidentiary and specific to this tree: the interop
// matrix in internal/livingreadme is keyed by protocol name, so a variant earns
// a published, CI-verified row proving the forced mode works against a real
// peer. A flag earns nothing, and a mode with no cell runs in no CI shard --
// which is to say it never runs at all.
//
// Variants live in their own namespace rather than in `protocols`, so that
// counts of "production protocols" stay counts of protocols. pq-ikev2 is not a
// seventeenth protocol; it is ikev2 with a floor under it. See
// doc/pq-variants-plan.md.
package client

import (
	"fmt"
	"sort"
)

var (
	// Guarded by mu, alongside protocols: Dial resolves both in one lookup and
	// a separate mutex would only invite a lock-ordering bug.
	variantParse = map[string]ParseFunc{}
	variantBase  = map[string]string{}

	// Guarded by serverMu, alongside serverParse, for the same reason.
	serverVariantParse = map[string]ServerParseFunc{}
	serverVariantBase  = map[string]string{}
)

// RegisterVariant makes name dialable as a variant of base. It is intended to
// be called from a variant package's init function, and panics on a duplicate,
// an empty name, or a base that is itself a variant -- all three are
// programming errors, detected at startup.
//
// It deliberately does NOT require base to be registered yet. Package
// initialisation order across two facades is not something a variant should
// depend on, and BaseOf is the only consumer of the link.
func RegisterVariant(name, base string, parse ParseFunc) {
	if name == "" {
		panic("client: RegisterVariant with an empty name")
	}
	if base == "" {
		panic("client: RegisterVariant with an empty base for " + name)
	}
	if parse == nil {
		panic("client: RegisterVariant with a nil ParseFunc for " + name)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := protocols[name]; dup {
		panic("client: variant name collides with a protocol: " + name)
	}
	if _, dup := variantParse[name]; dup {
		panic("client: variant registered twice: " + name)
	}
	if _, chained := variantBase[base]; chained {
		panic("client: variant base is itself a variant: " + base)
	}
	variantParse[name] = parse
	variantBase[name] = base
}

// RegisterServerVariant is the server-side counterpart of RegisterVariant.
func RegisterServerVariant(name, base string, parse ServerParseFunc) {
	if name == "" {
		panic("client: RegisterServerVariant with an empty name")
	}
	if base == "" {
		panic("client: RegisterServerVariant with an empty base for " + name)
	}
	if parse == nil {
		panic("client: RegisterServerVariant with a nil ServerParseFunc for " + name)
	}
	serverMu.Lock()
	defer serverMu.Unlock()
	if _, dup := serverParse[name]; dup {
		panic("client: server variant name collides with a protocol: " + name)
	}
	if _, dup := serverVariantParse[name]; dup {
		panic("client: server variant registered twice: " + name)
	}
	if _, chained := serverVariantBase[base]; chained {
		panic("client: server variant base is itself a variant: " + base)
	}
	serverVariantParse[name] = parse
	serverVariantBase[name] = base
}

// Variants lists the registered client variant names, sorted.
func Variants() []string {
	mu.RLock()
	defer mu.RUnlock()
	return sortedKeys(variantParse)
}

// ServerVariants lists the registered server variant names, sorted.
func ServerVariants() []string {
	serverMu.RLock()
	defer serverMu.RUnlock()
	return sortedKeys(serverVariantParse)
}

// AllProtocols lists every dialable name -- protocols and variants together,
// sorted. This is what a CLI usage message or a validity check should use;
// Protocols() is the narrower list that "how many protocols does veepin speak"
// is counted from.
func AllProtocols() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := sortedKeys(protocols)
	out = append(out, sortedKeys(variantParse)...)
	sort.Strings(out)
	return out
}

// AllServerProtocols is the server-side counterpart of AllProtocols.
func AllServerProtocols() []string {
	serverMu.RLock()
	defer serverMu.RUnlock()
	out := sortedKeys(serverParse)
	out = append(out, sortedKeys(serverVariantParse)...)
	sort.Strings(out)
	return out
}

// BaseOf returns the protocol that name varies, or "" when name is not a
// variant. It consults both registries, so it answers for a name registered on
// either side alone.
func BaseOf(name string) string {
	mu.RLock()
	base, ok := variantBase[name]
	mu.RUnlock()
	if ok {
		return base
	}
	serverMu.RLock()
	defer serverMu.RUnlock()
	return serverVariantBase[name]
}

// IsVariant reports whether name is a registered variant on either side.
func IsVariant(name string) bool { return BaseOf(name) != "" }

// sortedKeys is the shared body of the four listing functions above. Callers
// hold the appropriate lock.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lookupParse resolves a dialable name to its ParseFunc, checking protocols
// first and variants second. The order matters only for the error message: a
// name cannot be in both, because RegisterVariant panics on the collision.
func lookupParse(name string) (ParseFunc, bool) {
	mu.RLock()
	defer mu.RUnlock()
	if parse, ok := protocols[name]; ok {
		return parse, true
	}
	parse, ok := variantParse[name]
	return parse, ok
}

// lookupServerParse is the server-side counterpart of lookupParse.
func lookupServerParse(name string) (ServerParseFunc, bool) {
	serverMu.RLock()
	defer serverMu.RUnlock()
	if parse, ok := serverParse[name]; ok {
		return parse, true
	}
	parse, ok := serverVariantParse[name]
	return parse, ok
}

// ErrVariantOptionForced is returned by a variant's parse function when the
// caller supplied a value for an option the variant does not leave free.
//
// It exists so the refusal is loud. A variant that silently overrode the
// operator's explicit choice would be the same failure as a hardening switch
// that quietly does nothing: the operator believes one thing is configured and
// another is running. See doc/security.md on why mlockall aborts rather than
// warns.
var ErrVariantOptionForced = fmt.Errorf("option is forced by this protocol variant")

// ForcedOptionError builds the error a variant returns when an operator sets an
// option the variant controls, naming the value the variant requires.
func ForcedOptionError(variant, key, forced string) error {
	return fmt.Errorf("%s: %s: %w (it is always %q here; use %s to choose)",
		variant, key, ErrVariantOptionForced, forced, BaseOf(variant))
}

// ParseWithBase runs the base protocol's own registered ParseFunc over opts.
//
// This is how a variant reuses everything: option parsing, defaults,
// validation, credential loading and construction all stay in the base facade,
// and the variant contributes exactly the options it injects. A variant that
// reimplements any of that has taken on a second copy of the base's surface to
// keep in sync, which is the failure this exists to prevent.
func ParseWithBase(base string, opts map[string]string) (Dialer, error) {
	mu.RLock()
	parse, ok := protocols[base]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("client: variant base %w %q", ErrUnknownProtocol, base)
	}
	return parse(opts)
}

// ParseServerWithBase is the server-side counterpart of ParseWithBase.
func ParseServerWithBase(base string, opts map[string]string) (Server, error) {
	serverMu.RLock()
	parse, ok := serverParse[base]
	serverMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("client: variant base %w %q", ErrUnknownProtocol, base)
	}
	return parse(opts)
}

// AllVariants lists every registered variant name on either side, sorted and
// deduplicated. A variant is normally registered for both roles, so this is
// usually the same list as Variants(); it exists so a guard that means "every
// variant in the tree" cannot miss one that registered only a server.
func AllVariants() []string {
	seen := map[string]bool{}
	for _, n := range Variants() {
		seen[n] = true
	}
	for _, n := range ServerVariants() {
		seen[n] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
