package dataplane

import (
	"encoding/binary"
	"net/netip"
)

// routeTable maps an inner IP destination to the tunnel that carries it, by
// longest-prefix match. Both address families are held side by side: a v4 trie
// (32 bits) and a v6 trie (128 bits), selected per lookup by the address family,
// so a dual-stack tunnel can own both a v4 and a v6 prefix.
//
// A single-host route would do for IKEv2, where every client owns exactly one
// assigned address per family, but WireGuard's cryptokey routing gives each peer
// a set of prefixes (AllowedIPs) and picks the most specific match. Both fit
// here: a /32 or /128 is just a full-length prefix, and a client's "everything
// goes to the server" is 0.0.0.0/0 or ::/0.
//
// Each trie is an uncompressed binary trie over its address bits. Depth is
// bounded by the prefix length, so the common shapes are cheap: a lone default
// route resolves at the root, and the walk stops as soon as it runs out of
// children.
//
// # Persistent, so a reader never takes a lock
//
// No node is ever modified once it is reachable. insert and remove copy the
// nodes along the one path they change and leave every other subtree shared,
// so a routeTable value is a snapshot: the pump publishes one through an
// atomic pointer and its packet path reads that snapshot with no lock at all,
// while a writer builds the next. The cost lands on the writer, which pays at
// most one node per prefix bit -- 33 for an IPv4 host route -- and writers run
// at SA-lifetime rate, not packet rate.
//
// That property is what the code below has to preserve. Anything that writes
// through a node pointer it did not just allocate corrupts a snapshot another
// goroutine may be walking.
type routeTable struct {
	root4 *routeNode
	root6 *routeNode
}

type routeNode struct {
	child [2]*routeNode
	val   bound
	set   bool
}

// addrBits is an address read once into machine words, so a walk extracts each
// bit with a shift rather than re-converting the address per bit. That
// re-conversion -- As4 or As16 on every step of a walk up to 128 deep -- was a
// tenth of the outbound path's CPU when it was profiled.
//
// IPv4 occupies the top 32 bits of hi; IPv6 fills hi and lo.
type addrBits struct{ hi, lo uint64 }

func bitsOf(a netip.Addr) addrBits {
	if a.Is4() {
		b := a.As4()
		return addrBits{hi: uint64(binary.BigEndian.Uint32(b[:])) << 32}
	}
	b := a.As16()
	return addrBits{hi: binary.BigEndian.Uint64(b[:8]), lo: binary.BigEndian.Uint64(b[8:])}
}

// bit returns bit i of the address (0 = most significant).
func (b addrBits) bit(i int) uint8 {
	if i < 64 {
		return uint8(b.hi>>(63-uint(i))) & 1
	}
	return uint8(b.lo>>(127-uint(i))) & 1
}

// rootFor returns the address of the trie root for a's family.
func (t *routeTable) rootFor(a netip.Addr) **routeNode {
	if a.Is4() {
		return &t.root4
	}
	return &t.root6
}

// insert adds or replaces the entry for p. The prefix's family selects the trie.
func (t *routeTable) insert(p netip.Prefix, v bound) {
	p = p.Masked()
	root := t.rootFor(p.Addr())
	*root = withEntry(*root, bitsOf(p.Addr()), 0, p.Bits(), v, true)
}

// withEntry returns a copy of n with the entry at depth `bits` along a's path
// set to v (or cleared, when set is false). Only the path is copied.
func withEntry(n *routeNode, a addrBits, depth, bits int, v bound, set bool) *routeNode {
	var cp routeNode
	if n != nil {
		cp = *n
	}
	if depth == bits {
		cp.val, cp.set = v, set
		if !set {
			cp.val = bound{}
		}
		return &cp
	}
	b := a.bit(depth)
	cp.child[b] = withEntry(cp.child[b], a, depth+1, bits, v, set)
	return &cp
}

// remove drops p's entry. Interior nodes are left in place: route sets are small
// and churn with SA lifetime, not per packet, so pruning would buy nothing.
func (t *routeTable) remove(p netip.Prefix) {
	p = p.Masked()
	if n := t.node(p); n != nil && n.set {
		root := t.rootFor(p.Addr())
		*root = withEntry(*root, bitsOf(p.Addr()), 0, p.Bits(), bound{}, false)
	}
}

// removeOwned drops p's entry only while owner still holds it.
//
// Make-before-break SA replacement — install the new tunnel, then retire the old
// — has both tunnels claiming the same prefix, and insert has already handed it
// to the new one. An unconditional remove on the way past would tear out the
// live route and black-hole every outbound packet from then on.
func (t *routeTable) removeOwned(p netip.Prefix, owner Tunnel) {
	p = p.Masked()
	if n := t.node(p); n != nil && n.set && n.val.t == owner {
		root := t.rootFor(p.Addr())
		*root = withEntry(*root, bitsOf(p.Addr()), 0, p.Bits(), bound{}, false)
	}
}

// node walks to p's node, or nil when the trie has no branch that far. p must
// already be masked.
func (t *routeTable) node(p netip.Prefix) *routeNode {
	n := *t.rootFor(p.Addr())
	a := bitsOf(p.Addr())
	for i := 0; n != nil && i < p.Bits(); i++ {
		n = n.child[a.bit(i)]
	}
	return n
}

// lookup returns the entry whose prefix matches a most specifically; its t is
// nil when nothing does. The address family selects the trie; the walk length
// is the family's bit width.
func (t *routeTable) lookup(a netip.Addr) bound {
	n := *t.rootFor(a)
	bits := a.BitLen() // 32 for v4, 128 for v6
	ab := bitsOf(a)
	var best bound
	for i := 0; n != nil; i++ {
		if n.set {
			best = n.val
		}
		if i == bits {
			break
		}
		n = n.child[ab.bit(i)]
	}
	return best
}

// empty reports whether any route is installed in either family.
func (t *routeTable) empty() bool { return t.root4 == nil && t.root6 == nil }
