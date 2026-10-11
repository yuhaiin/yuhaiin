package dataplane

import (
	"sync/atomic"
	"time"
)

// Traffic accounting for the data path.
//
// Before this, nothing anywhere in the tree counted a byte. client.PeerInfo
// carried an ID, an address, a state and a last handshake, so the management
// panel could tell an operator that a peer handshook and nothing about whether
// it had moved a packet since -- and the one question every VPN operator asks,
// *is this thing actually carrying traffic*, had no answer anywhere, including
// in the logs. It was also the missing half of the shaping and throughput work:
// bench.sh and the interop iperf3 table measure the data path in a lab, and a
// running server reported nothing.
//
// # Where the counters live, and what that costs
//
// Per tunnel, as struct fields reached through a lookup the packet path was
// already doing -- not a keyed map consulted per packet, which is exactly how
// counting undoes an allocation-free path.
//
//   - Both directions are free. The inbound demux map and the outbound route
//     trie each hold a bound -- the tunnel and its counters together -- so the
//     lookup a packet already does finds its counters too. Outbound used to pay
//     a second, pointer-keyed map read under the lock for them; the lock-free
//     snapshot (pump.go's view) was the occasion to thread them through the
//     trie instead.
//
// Both are atomics, so a reader (the management API) never blocks the data path
// and the data path never blocks on a reader.
//
// # Drops
//
// Counted by reason rather than in total. "1,412 packets dropped" tells an
// operator nothing they can act on; "1,412 dropped with an unknown key" says a
// peer is sending under an SA this server has forgotten, and "1,412 dropped
// with no route" says the opposite -- a client sending to a destination nobody
// claims. The reasons are the ones the drop path already distinguishes.

// TunnelCounters is one tunnel's live traffic counters. All fields are atomic:
// the data path writes them without a lock and the management API reads them
// without taking one.
type TunnelCounters struct {
	rxPackets atomic.Uint64
	rxBytes   atomic.Uint64
	txPackets atomic.Uint64
	txBytes   atomic.Uint64
	// lastSeen is unix-nanos of the most recent authenticated inbound packet on
	// this tunnel. Distinct from the pump's own lastInbound, which is the
	// any-tunnel liveness clock: on a server those are the same number only
	// when there is one client.
	lastSeen atomic.Int64
}

// countRx records an authenticated inbound packet of n inner bytes, seen at
// now (unix nanos). The caller reads the clock once for a whole batch.
func (c *TunnelCounters) countRx(n int, now int64) {
	if c == nil {
		return
	}
	c.rxPackets.Add(1)
	c.rxBytes.Add(uint64(n))
	c.lastSeen.Store(now)
}

// countTx records an outbound packet of n inner bytes.
//
// Inner bytes, deliberately: it is what the user's traffic actually is, it is
// comparable with the Rx figure, and it is the number an operator is trying to
// reconcile against an application's own accounting. Encapsulation overhead is
// a property of the protocol and a constant per packet, so anyone who wants the
// on-the-wire figure can compute it; the reverse is not true.
func (c *TunnelCounters) countTx(n int) {
	if c == nil {
		return
	}
	c.txPackets.Add(1)
	c.txBytes.Add(uint64(n))
}

// TunnelStats is a consistent-enough snapshot of one tunnel's counters. The
// four numbers are read separately, so a snapshot taken mid-packet can show a
// packet counted and its bytes not yet -- which is a discrepancy of one packet
// in a number that only ever grows, and is the right trade against locking the
// data path to read a gauge.
type TunnelStats struct {
	RxPackets uint64 `json:"rx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
	// LastSeen is when an authenticated packet last arrived, or the zero time
	// if none ever has.
	LastSeen time.Time `json:"last_seen"`
}

// Snapshot reads the counters.
func (c *TunnelCounters) Snapshot() TunnelStats {
	if c == nil {
		return TunnelStats{}
	}
	s := TunnelStats{
		RxPackets: c.rxPackets.Load(),
		RxBytes:   c.rxBytes.Load(),
		TxPackets: c.txPackets.Load(),
		TxBytes:   c.txBytes.Load(),
	}
	if ns := c.lastSeen.Load(); ns != 0 {
		s.LastSeen = time.Unix(0, ns)
	}
	return s
}

// add accumulates another snapshot, for the pump-wide total.
func (s *TunnelStats) add(o TunnelStats) {
	s.RxPackets += o.RxPackets
	s.RxBytes += o.RxBytes
	s.TxPackets += o.TxPackets
	s.TxBytes += o.TxBytes
	if o.LastSeen.After(s.LastSeen) {
		s.LastSeen = o.LastSeen
	}
}

// DropReason names why the data path discarded a packet. The set is exactly the
// distinctions the drop path already made, because a reason nothing can produce
// is a metric that reads as "never happens" while the real cause is folded into
// another bucket.
type DropReason int

const (
	// DropNoKey: the demux found no tunnel key in the datagram. Junk, a scan,
	// or a protocol framing mismatch.
	DropNoKey DropReason = iota
	// DropUnknownKey: a well-formed key naming a tunnel this pump does not
	// have. A peer sending under an SA that has been retired or forgotten --
	// the signature of a rekey that went wrong at one end only.
	DropUnknownKey
	// DropDecapFailed: authentication or decryption failed. Corruption, replay,
	// or a key mismatch.
	DropDecapFailed
	// DropNotIP: a TUN read that was not an IP packet we can route.
	DropNotIP
	// DropNoRoute: an inner destination no tunnel claims. On a server, a client
	// sending somewhere the pool does not cover.
	DropNoRoute
	// DropTooBig: over the inner MTU. Not silent -- an ICMP fragmentation-needed
	// goes back -- but still a packet that did not cross, and a rising count is
	// how path-MTU trouble shows up.
	DropTooBig
	// DropEncapFailed: the tunnel could not encapsulate. A dead SA, or a key
	// that has been rotated out from under an in-flight packet.
	DropEncapFailed
	// DropTUNWrite: the TUN device rejected the write. The interface is down or
	// the queue is full.
	DropTUNWrite
	// DropPacerFull: a paced tunnel's send queue was full, so an outbound
	// packet was discarded rather than waiting.
	//
	// It is its own reason because it means something no other drop does: the
	// offered load exceeded the tunnel's configured rate. A constant-rate
	// tunnel cannot go faster to absorb a burst -- that is the property it
	// exists to provide -- so this counter rising is the operator's signal that
	// the rate is set below what the traffic wants, and folding it into
	// encap_failed would present a configuration choice as a fault.
	DropPacerFull
	numDropReasons
)

// String is the metric label, so it is snake_case and stable: changing one
// breaks whatever dashboard is reading it.
func (r DropReason) String() string {
	switch r {
	case DropNoKey:
		return "no_key"
	case DropUnknownKey:
		return "unknown_key"
	case DropDecapFailed:
		return "decap_failed"
	case DropNotIP:
		return "not_ip"
	case DropNoRoute:
		return "no_route"
	case DropTooBig:
		return "too_big"
	case DropEncapFailed:
		return "encap_failed"
	case DropTUNWrite:
		return "tun_write"
	case DropPacerFull:
		return "pacer_full"
	default:
		return "unknown"
	}
}

// PumpStats is everything one pump can say about the traffic it moved.
type PumpStats struct {
	// Total sums every tunnel's counters, including tunnels that have since
	// been removed -- a peer that disconnected still carried what it carried,
	// and a total that goes down is a total nobody can reason about.
	Total TunnelStats `json:"total"`
	// Tunnels is how many are registered right now.
	Tunnels int `json:"tunnels"`
	// Drops is keyed by DropReason.String().
	Drops map[string]uint64 `json:"drops"`
}
