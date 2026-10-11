// The client-side counterpart of RegisterServerOpts: metadata about the keys a
// protocol's Dial ParseFunc reads, plus the spec helpers for the options every
// protocol shares. OptSpec's own contract is documented on the type in
// server.go; this file does not restate it.
package client

import (
	"fmt"
	"maps"
	"sort"
	"sync"
)

var (
	clientOptsMu sync.RWMutex
	clientOpts   = map[string][]OptSpec{}
)

// RegisterClientOpts declares option metadata for a protocol's Dial surface,
// alongside its Register side-effect call. It is optional — a protocol that
// skips it is still dialable, but callers that render or validate options by
// schema fall back to a free-form editor. Like Register it is meant for an
// init(). Panics on a duplicate name to surface a registration bug at startup.
func RegisterClientOpts(protocol string, opts []OptSpec) {
	if protocol == "" {
		panic("client: RegisterClientOpts with an empty protocol name")
	}
	clientOptsMu.Lock()
	defer clientOptsMu.Unlock()
	if _, dup := clientOpts[protocol]; dup {
		panic("client: client opts registered twice: " + protocol)
	}
	clientOpts[protocol] = opts
}

// ClientOptsFor returns the claimed metadata for a registered client protocol,
// or nil/false when the facade did not declare any.
// Like ServerOptsFor, a variant falls back to the protocol it varies.
func ClientOptsFor(protocol string) ([]OptSpec, bool) {
	clientOptsMu.RLock()
	opts, ok := clientOpts[protocol]
	clientOptsMu.RUnlock()
	if ok {
		return opts, true
	}
	if base := BaseOf(protocol); base != "" {
		return ClientOptsFor(base)
	}
	return nil, false
}

// Redacted is the placeholder a redacted option value carries. It is part of
// the management API's contract in both directions: a GET returns it in place
// of every secret, and a PATCH that submits it back means "keep the stored
// value" rather than "set the secret to this literal string".
const Redacted = "<redacted>"

// Redact returns a copy of opts with the value of every key the specs mark
// Secret replaced by Redacted. Keys absent from specs, and secrets that are
// empty anyway, are copied through untouched; a nil map stays nil.
//
// One function for three call sites that were three copies: the management
// API's server-side redaction, its client-side one, and `veepin profile show`.
// The only thing that ever differed between them was which registry the specs
// came from, so the specs are the parameter and the caller picks -- ServerOptsFor
// for a listener, ClientOptsFor for a profile.
func Redact(specs []OptSpec, opts map[string]string) map[string]string {
	if opts == nil {
		return nil
	}
	out := make(map[string]string, len(opts))
	maps.Copy(out, opts)
	for _, spec := range specs {
		if !spec.Secret {
			continue
		}
		if v, has := out[spec.Key]; has && v != "" {
			out[spec.Key] = Redacted
		}
	}
	return out
}

// ValidateOptions runs a protocol's ParseFunc over opts and reports whether it
// would accept them, discarding the Dialer it builds. It performs no I/O: a
// ParseFunc validates and assembles configuration, and Dial is what connects.
//
// It exists so a caller can tell an operator that a profile is unusable at the
// point they save it rather than at the point they dial it, and so
// TestRequiredClientOptsAreTheOnesTheParseRejects can hold each facade's
// Required flags against the parse that enforces them.
func ValidateOptions(protocol string, opts map[string]string) error {
	parse, ok := lookupParse(protocol)
	if !ok {
		return fmt.Errorf("client: %w %q", ErrUnknownProtocol, protocol)
	}
	if _, err := parse(opts); err != nil {
		return fmt.Errorf("client: %s: %w", protocol, err)
	}
	return nil
}

// TUNOpt is the spec for a protocol's TUN-interface-name option. Thirty of
// these were spelled out identically across the seventeen facades, differing
// only in which const held the string "tun".
//
// The point of collapsing them is not the saved lines. A table where the shared
// rows are one call each says only what that protocol does differently, so an
// option carrying an unusual flag stands out as the row that is written out in
// full -- which is how the l2tpv3 and openvpn Secret disagreements survived
// review sitting in plain sight.
func TUNOpt(key string) OptSpec {
	return OptSpec{Key: key, Kind: OptStr, Help: "TUN interface name (empty = kernel picks)"}
}

// ShapeOpt is the spec for a protocol's traffic-shaping budget. direction is the
// word that describes which way the padding is applied from this end's point of
// view -- "upstream" on a client, "downstream" on a server, "outbound" where the
// protocol is symmetric.
//
// A protocol whose shaping needs more said than that (l2tpv3 pads only the
// frames that carry IP) writes its own spec out in full, which is the intended
// signal.
func ShapeOpt(key, direction string) OptSpec {
	return OptSpec{
		Key:     key,
		Kind:    OptInt,
		Default: "0",
		Help:    "per-flow " + direction + " shaping budget in bytes (0 = off)",
	}
}

// ClientProtocolsWithOpts lists every protocol that declared client OptSpec
// metadata, sorted. The management panel uses it to decide which profiles get a
// typed form.
func ClientProtocolsWithOpts() []string {
	clientOptsMu.RLock()
	defer clientOptsMu.RUnlock()
	names := make([]string, 0, len(clientOpts))
	for name := range clientOpts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
