// Package pq registers "pq-anyconnect": AnyConnect with the post-quantum contract in
// force -- ML-KEM key exchange and ML-DSA authentication, with anything less
// refused rather than negotiated down.
//
// It contains no protocol code, and that is the design. The variant injects the
// options that put the base facade into post-quantum-only mode and hands the map
// to anyconnect's own registered parse function, so every default, every validation,
// every credential path and the whole construction sequence stay in exactly one
// place. A variant that reimplemented any of that would be a second copy of the
// base's surface, drifting from the first.
//
// The same reasoning is why this package declares no OptSpec table:
// client.ServerOptsFor falls back to the base, so `veepin serve pq-anyconnect`
// renders byte-for-byte the flag set of `veepin serve anyconnect`.
//
// See doc/pq-variants-plan.md; what pq- guarantees is in internal/pqpolicy.
package pq

import (
	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/pqpolicy"

	_ "github.com/xen0bit/veepin/anyconnect" // the base this varies
)

const (
	name = "pq-anyconnect"
	base = "anyconnect"
)

func init() {
	client.RegisterVariant(name, base, dial)
	client.RegisterServerVariant(name, base, serve)
}

// forced are the options this variant pins beyond the post-quantum marker
// itself. internal/dtls is a from-scratch DTLS 1.2 with two fixed
// suites and no post-quantum path at all, so leaving the UDP data channel bound
// would mean a post-quantum control channel in front of a classical data path --
// the name would be describing the handshake and not the traffic. Setting
// -no-dtls explicitly to false is refused rather than silently overruled.
var forced = map[string]string{"no-dtls": "true"}

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
