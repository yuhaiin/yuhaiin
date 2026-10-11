package dataplane

// Deriving an inner MTU instead of guessing one.
//
// Every protocol in this tree used to carry a bare MTU literal — 1500, 1420,
// 1400, 1300, 1200 — with nothing saying where the number came from. Some are
// the protocol's own documented default; others were picked because they
// happened to work. Two of them had comments describing arithmetic that does
// not produce the number next to it.
//
// That matters more than untidiness suggests. An MTU that is too large is the
// black hole ICMP handling exists to answer; an MTU that is too small costs
// throughput on every packet forever. Neither is visible in a test — both
// endpoints agree, packets flow, and the loss shows up only as someone else's
// slow transfer.
//
// So the vocabulary lives here: what a path is assumed to carry, what each
// layer of encapsulation costs, and one function that subtracts. A protocol
// states its overhead as a sum whose terms can be checked against its own wire
// format, and the result is derived rather than asserted.
//
// # Why the conventional value still wins in two places
//
// Nebula ships 1300 and WireGuard ships 1420. Neither equals what the
// arithmetic here produces, and neither is wrong: they are what every other
// implementation of those protocols uses, and an MTU is only useful if the peer
// agrees with it. Those two keep their conventional default, with the derived
// value written alongside so the gap is deliberate and visible instead of
// being a number nobody could account for.

// Sizes of the headers a tunnel is wrapped in.
const (
	// DefaultPathMTU is what an ordinary ethernet path carries. It is the
	// assumption every one of these defaults rests on, and it is only an
	// assumption — a path crossing PPPoE or another tunnel carries less, which
	// is what ICMP fragmentation-needed exists to report.
	DefaultPathMTU = 1500

	// IPv4HeaderLen is a header with no options, which is what these data paths
	// send and what any sane router forwards.
	IPv4HeaderLen = 20
	// IPv6HeaderLen is the fixed header, with no extension headers.
	IPv6HeaderLen = 40
	// UDPHeaderLen is the UDP header.
	UDPHeaderLen = 8

	// MinInnerMTU is the smallest inner MTU worth offering. RFC 791 requires
	// every IPv4 host to accept 576 octets, so below this a tunnel cannot carry
	// traffic that any correspondent is obliged to handle.
	MinInnerMTU = 576

	// MinIPv6MTU is the IPv6 minimum link MTU (RFC 8200 §5): every IPv6 link must
	// carry 1280 octets, and a node must never lower its path MTU below it. An
	// ICMPv6 Packet Too Big therefore never advertises less than this.
	MinIPv6MTU = 1280
)

// OuterUDP4 is the cost of carrying a tunnel over UDP in IPv4: the outer IP
// header plus the UDP header. It is the common prefix of almost every overhead
// sum in this tree.
const OuterUDP4 = IPv4HeaderLen + UDPHeaderLen

// OuterUDP6 is the same for IPv6. A protocol that must work unchanged over
// either family sizes itself with this, since the larger header is the one that
// has to fit.
const OuterUDP6 = IPv6HeaderLen + UDPHeaderLen

// InnerMTU is the largest inner packet that still fits in a path of pathMTU
// octets once overhead octets of encapsulation are added.
//
// The result is clamped to MinInnerMTU. A derivation that lands below it means
// the path MTU being reported is too small for the protocol to work at all, and
// returning a negative or absurd MTU would turn that into a confusing failure
// somewhere further down instead of an obviously wrong number here.
func InnerMTU(pathMTU, overhead int) int {
	inner := pathMTU - overhead
	if inner < MinInnerMTU {
		return MinInnerMTU
	}
	return inner
}
