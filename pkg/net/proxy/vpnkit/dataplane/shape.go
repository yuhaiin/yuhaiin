package dataplane

// Downstream flow shaping: padding the data path so the *inner* traffic's
// packet-size pattern does not survive the tunnel's encryption.
//
// The threat is the encapsulated-TLS-handshake fingerprint (Xue et al., USENIX
// Security 2024, "Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS
// Handshakes"). It is protocol-agnostic and it does not care what cipher the
// tunnel uses: when a tunnel carries a user's TLS session, the inner handshake's
// sequence of packet sizes and directions is recoverable through the outer
// encryption, because one inner packet becomes one outer datagram of the inner
// size plus a fixed overhead. That is what defeated obfs4, Shadowsocks, VMess
// and Trojan, and it is why "make the bytes look random" is not a defence.
//
// Two properties of a VPN — as opposed to a single-stream proxy — make the
// defence cheap enough to turn on:
//
//   - The distinctive half of the fingerprint is *downstream*: the multi-KB
//     ServerHello and Certificate flight. Downstream is the direction the server
//     controls, so shaping it needs no client change at all. A stock Windows,
//     macOS, iOS or Android IKEv2 client, or an official WireGuard app, gets the
//     benefit unmodified. That is the whole reason this lives here.
//
//   - The attack keys on *handshakes*, which sit at the start of a flow. So the
//     strongest available padding can be applied to the first few kilobytes of
//     each inner flow and switched off afterwards. The cost is O(number of
//     flows), not O(bytes): a bulk transfer pays once, at the start, and its
//     steady-state throughput is untouched.
//
// What this deliberately does not do: it never delays or reorders a packet.
// Constant-rate shaping would also cover packet *counts* and inter-arrival
// times, which padding leaves exposed, but it would tax exactly the moment that
// is most latency-sensitive — the handshake. See doc/traffic-shaping.md for the
// full statement of what remains observable.

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// Shaping defaults. Bytes is sized so a TLS 1.2 handshake carrying a full
// certificate chain — the flight the fingerprint keys on — fits comfortably
// inside one flow's budget with room to spare.
const (
	DefaultShapeBytes    = 16384
	DefaultShapeIdle     = 30 * time.Second
	DefaultShapeMaxFlows = 4096
)

// sweepEvery bounds the cost of expiring idle flows: the table is swept once
// per this many shaped packets rather than on every one, so the sweep's O(n) is
// amortised away instead of landing on the data path.
const sweepEvery = 1024

// ShapeConfig configures downstream flow shaping. The zero value disables it,
// which is the behaviour from before it existed.
type ShapeConfig struct {
	// Bytes is how much padded output each inner flow is given before shaping
	// stops for that flow — so it bounds what shaping costs, and a flow gets
	// Bytes/mtu shaped packets whatever sizes it carries. Zero disables shaping
	// entirely.
	Bytes int
	// Idle re-arms a flow's budget after this much silence, so a reused
	// connection carrying a second handshake is shaped again.
	Idle time.Duration
	// MaxFlows bounds the flow table.
	MaxFlows int
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// withDefaults fills unset fields. Bytes is left alone: zero means "off", not
// "use the default", so a caller cannot enable shaping by accident.
func (c ShapeConfig) withDefaults() ShapeConfig {
	if c.Idle <= 0 {
		c.Idle = DefaultShapeIdle
	}
	if c.MaxFlows <= 0 {
		c.MaxFlows = DefaultShapeMaxFlows
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// flowKey identifies one inner flow. It is a comparable struct so it can be a
// map key directly, with no allocation and no hashing of a byte slice on the
// data path.
type flowKey struct {
	src, dst     netip.Addr
	sport, dport uint16
	proto        uint8
}

// flowState is stored by value: updating an existing flow is a plain map
// assignment, which allocates nothing once the table has grown.
type flowState struct {
	remaining int   // shaping budget left, in bytes of padded output
	lastSeen  int64 // unix nanos, for idle expiry and re-arm
}

// Shaper decides how much each outbound packet should be padded.
//
// It is owned by a single goroutine — the pump's TUN reader, which is the only
// caller of routeOutbound and sendSegments — so it carries no lock, on the same
// reasoning that leaves groTable unlocked. Splitting the data path across cores
// (doc/scaling-the-data-path.md) requires giving each worker its own Shaper, or
// sharding this table by flow, before that assumption can be relaxed.
type Shaper struct {
	cfg   ShapeConfig
	flows map[flowKey]flowState
	since int // packets since the last idle sweep
}

// NewShaper builds a shaper from cfg. A cfg whose Bytes is zero yields a shaper
// whose Target is always 0, so callers need not special-case "shaping off".
func NewShaper(cfg ShapeConfig) *Shaper {
	return &Shaper{
		cfg:   cfg.withDefaults(),
		flows: make(map[flowKey]flowState),
	}
}

// Target reports the inner size pkt should be padded to before encapsulation,
// or 0 for "send it as it is". mtu is the largest inner packet the path can
// carry; the returned target never exceeds it, so padding can never turn a
// deliverable packet into an oversized one.
//
// While a flow has budget the target is the full inner MTU. Quantising to a
// ladder of smaller size classes would be cheaper, but every distinct class
// left in place is signal the classifier can still use; one size is the
// strongest answer, and the per-flow budget is what makes it affordable.
//
// A nil Shaper is valid and always returns 0, so an unshaped pump costs one
// nil check per packet.
func (s *Shaper) Target(pkt []byte, mtu int) int {
	if s == nil || s.cfg.Bytes <= 0 || mtu <= 0 {
		return 0
	}
	key, ok := flowKeyOf(pkt)
	if !ok {
		return 0 // not a packet we can attribute to a flow
	}
	now := s.cfg.Now().UnixNano()
	idle := int64(s.cfg.Idle)

	st, seen := s.flows[key]
	switch {
	case !seen:
		st = flowState{remaining: s.cfg.Bytes}
	case now-st.lastSeen >= idle:
		// Silent long enough that whatever comes next is a new exchange —
		// a reused connection, or a renegotiation — so shape it again.
		st.remaining = s.cfg.Bytes
	}
	st.lastSeen = now
	shape := st.remaining > 0
	if shape {
		// Charge the budget what this packet will *emit*, not what it carries.
		// Charging the inner length instead let a flow of small packets run far
		// past the budget's apparent cost: at 60-octet packets a 16 KiB budget
		// shaped 273 of them and put 382 KiB on the wire. Charging the emitted
		// size makes Bytes bound what shaping actually costs, and makes the
		// number of shaped packets a flow gets deterministic — Bytes/mtu — which
		// is what lets the count be normalised rather than merely bounded.
		st.remaining -= max(len(pkt), mtu)
	}
	s.store(key, st)

	// Budget spent is the steady-state path for bulk transfer, and it must stay
	// free: one map lookup and one comparison, no padding.
	if !shape || len(pkt) >= mtu {
		return 0
	}
	return mtu
}

// store writes a flow back, bounding the table on the way in.
func (s *Shaper) store(key flowKey, st flowState) {
	if _, exists := s.flows[key]; !exists && len(s.flows) >= s.cfg.MaxFlows {
		// Every entry is a cache the next packet of that flow rebuilds, so
		// dropping the table is safe: the worst outcome is that some flows are
		// shaped again from the start. That is a far better failure than an
		// unbounded map, and it matches how PacketConn bounds its peer table.
		clear(s.flows)
	}
	s.flows[key] = st

	if s.since++; s.since >= sweepEvery {
		s.since = 0
		s.sweep(st.lastSeen)
	}
}

// sweep drops flows idle for longer than the re-arm interval. An entry that
// expires and reappears is simply shaped again, which is the conservative
// direction to be wrong in.
func (s *Shaper) sweep(now int64) {
	idle := int64(s.cfg.Idle)
	for k, st := range s.flows {
		if now-st.lastSeen >= idle {
			delete(s.flows, k)
		}
	}
}

// Ethernet header constants for the layer-2 shaping path.
const (
	ethHeaderLen  = 14
	ethTypeIPv4   = 0x0800
	ethTypeIPv6   = 0x86dd
	ethTypeOffset = 12
)

// ShapeableFrame reports whether an Ethernet frame may be padded.
//
// Only IPv4 and IPv6 payloads may. Padding works everywhere else in this tree
// because the receiver trims by the inner IP header's own Total Length, with
// nothing negotiated -- see TrimToIP. Ethernet has no length field of its own,
// so a padded ARP or STP frame has nothing to trim by and would reach the peer
// with trailing rubbish attached. Rather than pad what cannot be trimmed, a
// layer-2 shaper leaves non-IP frames alone; they are a small and bursty
// minority, which is stated plainly in the caveats rather than papered over.
func ShapeableFrame(frame []byte) bool {
	if len(frame) < ethHeaderLen {
		return false
	}
	switch binary.BigEndian.Uint16(frame[ethTypeOffset:]) {
	case ethTypeIPv4, ethTypeIPv6:
		return true
	}
	return false
}

// TargetFrame is Target for an Ethernet frame: it keys the flow off the
// encapsulated IP packet, so a layer-2 tunnel shapes by the same per-flow
// budget as every layer-3 one. mtu is the frame-level target, Ethernet header
// included.
//
// A frame carrying anything but IP returns 0 -- see ShapeableFrame.
func (s *Shaper) TargetFrame(frame []byte, mtu int) int {
	if s == nil {
		return 0
	}
	if !ShapeableFrame(frame) {
		return 0
	}
	inner := s.Target(frame[ethHeaderLen:], mtu-ethHeaderLen)
	if inner <= 0 {
		return 0
	}
	return inner + ethHeaderLen
}

// flowKeyOf extracts the inner 5-tuple. Ports are read only for the transports
// that have them at a fixed offset and only from a first fragment; anything
// else groups by addresses and protocol alone, which is coarser but never
// wrong — the key only has to be stable for the packets of one exchange.
func flowKeyOf(pkt []byte) (flowKey, bool) {
	var k flowKey
	if len(pkt) < 1 {
		return k, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return k, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || ihl > len(pkt) {
			return k, false
		}
		k.src = netip.AddrFrom4([4]byte(pkt[12:16]))
		k.dst = netip.AddrFrom4([4]byte(pkt[16:20]))
		k.proto = pkt[9]
		// Only a first fragment carries the transport header; a later one has a
		// non-zero offset and its ports would be read out of the payload.
		if binary.BigEndian.Uint16(pkt[6:8])&0x1fff == 0 {
			k.sport, k.dport = portsOf(k.proto, pkt[ihl:])
		}
		return k, true
	case 6:
		if len(pkt) < 40 {
			return k, false
		}
		k.src = netip.AddrFrom16([16]byte(pkt[8:24]))
		k.dst = netip.AddrFrom16([16]byte(pkt[24:40]))
		// Extension headers are not walked: a packet carrying them keys on
		// addresses and its first next-header value, which still groups that
		// flow's packets together.
		k.proto = pkt[6]
		k.sport, k.dport = portsOf(k.proto, pkt[40:])
		return k, true
	}
	return k, false
}

// portsOf reads the source and destination ports of the transports that place
// them in the first four octets of their header.
func portsOf(proto uint8, rest []byte) (sport, dport uint16) {
	switch proto {
	case 6, 17, 132: // TCP, UDP, SCTP
		if len(rest) < 4 {
			return 0, 0
		}
		return binary.BigEndian.Uint16(rest[0:2]), binary.BigEndian.Uint16(rest[2:4])
	}
	return 0, 0
}

// TrimToIP cuts a decapsulated plaintext down to the length its own IP header
// declares, discarding any trailing filler.
//
// It is the receiving half of padding, and the reason padding is safe to add to
// a protocol whose peer never negotiated it: the inner packet delimits itself,
// so filler appended past its end is inert. WireGuard has always relied on this
// for its 16-octet alignment padding, and ESP's traffic-flow-confidentiality
// padding (RFC 4303 §2.7) is defined in exactly the same terms.
//
// A zero-length plaintext is an authenticated packet with nothing inside — a
// keepalive — and returns nil, which the caller must not write to the TUN. A
// plaintext whose declared length does not fit is rejected the same way, since
// a truthful header is the only thing making the trim meaningful.
func TrimToIP(plain []byte) []byte {
	if len(plain) == 0 {
		return nil // keepalive
	}
	switch plain[0] >> 4 {
	case 4:
		if len(plain) < 20 {
			return nil
		}
		total := int(binary.BigEndian.Uint16(plain[2:4]))
		if total < 20 || total > len(plain) {
			return nil
		}
		return plain[:total]
	case 6:
		if len(plain) < 40 {
			return nil
		}
		total := 40 + int(binary.BigEndian.Uint16(plain[4:6]))
		if total > len(plain) {
			return nil
		}
		return plain[:total]
	}
	return nil
}
