// Package goldens holds the committed peer captures and the assertions that
// must hold over them.
//
// The corpora are recorded from the live interop cells in tests/interop and
// committed here as text. Two things then run the same assertions over them:
//
//	goldens_test.go     the committed corpus, offline, in milliseconds
//	tests/interop/...   a corpus captured seconds ago, from a live peer
//
// That pairing is the answer to the obvious objection to golden files. A
// recording pins the peer as it was on the capture date and cannot notice that
// the peer changed; running the identical [Golden.Check] against a fresh
// capture in the interop shard is what notices. The committed corpus is the
// fast local proxy, the live cell is the evidence, and neither is asked to be
// the other.
//
// A check is deliberately allowed to be strict. If strongSwan stops sending
// IKEV2_FRAGMENTATION_SUPPORTED, veepin silently stops fragmenting its own IKE
// output and certificate authentication regresses to the bug item 1 of
// doc/claims-and-reach-plan.md existed to fix — invisibly, because the cert
// cell mints the smallest certificate that exists. A check that only asserted
// "it parses" would sail straight past that, which is the failure mode this
// package is a reaction to.
package goldens

import (
	"fmt"

	"github.com/xen0bit/veepin/internal/capture"
)

// Golden is one recorded cell: where it comes from, how a capture of it is
// turned into a corpus, and what must be true of the result.
type Golden struct {
	// Cell is the compose file the capture is taken from, so a reader can rerun
	// the thing that produced it.
	Cell string
	// Peer names the implementation and version, for the corpus's provenance.
	Peer string
	// Notes go at the head of the corpus file.
	Notes []string
	// Extract turns one pcap from that cell into labelled records. It is the
	// only place that knows what the protocol's messages are called.
	Extract func(pcap []byte) ([]capture.Record, error)
	// Check asserts whatever must hold. It runs against the committed corpus
	// offline and against a fresh capture in the interop shard, which is the
	// only reason it is an exported function rather than a test body.
	Check func(*capture.Corpus) error
}

// Registry maps a corpus name — the file's base name, without the extension —
// to its definition.
//
// Registry and the corpora directory are kept in step mechanically: a corpus
// with no entry is a file nothing reads, and an entry with no corpus is an
// assertion nothing runs. Both are silent failures, and the package's test
// fails on either.
var Registry = map[string]Golden{
	"ikev2-strongswan": {
		Cell: "compose.client-ss.yml",
		Peer: "strongSwan 6.0.0 (debian bookworm)",
		Notes: []string{
			"Direction A of the IKEv2 row: veepin initiator, strongSwan responder, PSK auth.",
			"Only the IKE_SA_INIT pair is readable without keys. The IKE_AUTH pair is kept",
			"as a framing check and as a fuzz seed of real encrypted messages.",
		},
		Extract: ExtractIKEv2,
		Check:   CheckIKEv2,
	},
	"wireguard-wgge": {
		Cell: "compose.wireguard-server.yml",
		Peer: "wireguard-go (wg-quick, alpine)",
		Notes: []string{
			"Direction B of the WireGuard row: a real wireguard-go initiator, veepin responding.",
			"That direction is deliberate. The initiation is the message with the MACs and the",
			"encrypted static key in it, so capturing the cell where the *peer* sends it is what",
			"lets veepin's responder be run against somebody else's arithmetic offline.",
		},
		Extract: ExtractWireGuard,
		Check:   CheckWireGuard,
	},
}

// Build assembles a corpus from a capture of the named cell.
//
// captured is the ISO date, passed in rather than taken from the clock so that
// regenerating a corpus is a deliberate act with a reviewable diff rather than
// something that changes every time a test runs.
func Build(name string, pcap []byte, captured string) (*capture.Corpus, error) {
	g, ok := Registry[name]
	if !ok {
		return nil, fmt.Errorf("goldens: no corpus named %q", name)
	}
	records, err := g.Extract(pcap)
	if err != nil {
		return nil, fmt.Errorf("goldens: %s: %w", name, err)
	}
	return &capture.Corpus{
		Cell:     g.Cell,
		Peer:     g.Peer,
		Captured: captured,
		Notes:    g.Notes,
		Records:  records,
	}, nil
}
