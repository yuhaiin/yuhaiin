// Package pq registers "pq-ikev2": IKEv2 with the post-quantum contract in
// force -- ML-KEM key exchange and ML-DSA authentication, with anything less
// refused rather than negotiated down.
//
// It contains no protocol code, and that is the design. The variant injects the
// options that put the base facade into post-quantum-only mode and hands the map
// to ikev2's own registered parse function, so every default, every validation,
// every credential path and the whole construction sequence stay in exactly one
// place. A variant that reimplemented any of that would be a second copy of the
// base's surface, drifting from the first.
//
// The same reasoning is why this package declares no OptSpec table:
// client.ServerOptsFor falls back to the base, so `veepin serve pq-ikev2`
// renders byte-for-byte the flag set of `veepin serve gp`.
//
// See doc/pq-variants-plan.md; what pq- guarantees is in internal/pqpolicy.
package pq

import (
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/pqpolicy"

	_ "github.com/xen0bit/veepin/ikev2" // the base this varies
)

const (
	name = "pq-ikev2"
	base = "ikev2"
)

func init() {
	client.RegisterVariant(name, base, dial)
	client.RegisterServerVariant(name, base, serve)
}

// forced are the options this variant pins beyond the post-quantum marker
// itself. Empty: the marker alone puts the responder into RequirePostQuantum
// and RequirePostQuantumAuth, and the -pq flag on the base protocol is a
// strictly weaker request that this variant subsumes rather than needs.
var forced = map[string]string(nil)

func dial(opts map[string]string) (client.Dialer, error) {
	o, err := pqpolicy.Force(name, opts, forced)
	if err != nil {
		return nil, err
	}
	pqpolicy.Announce(name)
	return client.ParseWithBase(base, o)
}

func serve(opts map[string]string) (client.Server, error) {
	o, err := pqpolicy.Force(name, opts, forced)
	if err != nil {
		return nil, err
	}
	pqpolicy.Announce(name)
	return client.ParseServerWithBase(base, o)
}
