package nebula

// Relays: carrying traffic through a third host when the two ends cannot
// reach each other directly.
//
// Hole punching (see lighthouse.go) opens NAT bindings by having both peers
// send outward at the same time. It works against most NATs and fails against
// the ones that matter most in practice — symmetric NAT and CGNAT, where the
// external port a peer sees is not the port the other peer must send to. A
// relay is the fallback: a third mesh member that both ends *can* reach agrees
// to forward between them.
//
//	    A ────X──── B        direct path blocked
//	     \         /
//	      \       /
//	       ▼     ▼
//	          R              both can reach R, so A─R─B carries the traffic
//
// # What the relay can and cannot see
//
// The relay forwards without decrypting. A relayed packet carries two nebula
// headers: an outer one addressed to the relay, and an inner one addressed to
// the far end, wrapping a payload encrypted end-to-end under A and B's own
// tunnel keys. The relay holds neither of those keys.
//
// The outer layer is therefore **authenticated but not encrypted** — the
// relay must read the inner header to know where to forward, so the inner
// header travels in the clear on that hop, with an AEAD tag over it that
// proves it came from the host the relay has a tunnel with. This is nebula's
// design and not a choice made here (`SendVia` in the reference calls
// `EncryptDanger` with a nil plaintext and the whole buffer as additional
// data). The consequence worth stating: **a relay learns who is talking to
// whom, and how much**, which is exactly the metadata a direct path would not
// have exposed. It cannot read the traffic.
//
// # The three-party state
//
// Setting up a relay involves three hosts and two half-relays, which is where
// the naming gets confusing enough to write down:
//
//   - On **A** and **B** (the ends), the relay entry is `relayTerminal`: "my
//     traffic for that peer goes out through this relay".
//   - On **R** (the middle), there are two entries, both `relayForwarding`:
//     one for A naming B as the peer, one for B naming A.
//
// A relay is negotiated with `CreateRelayRequest`/`CreateRelayResponse`
// control messages, which ride inside the already-established tunnels to R.
// The indices are the same kind of value as a tunnel's local index, and serve
// the same purpose: they are what the receiver demultiplexes an arriving
// relayed packet on.

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// Field numbers for NebulaControl, from the reference's nebula.proto. Fields 4
// and 5 are the deprecated IPv4-only address forms, which this implementation
// neither sends nor reads -- 6 and 7 carry an Addr and cover both families.
const (
	fieldControlType                = 1
	fieldControlInitiatorRelayIndex = 2
	fieldControlResponderRelayIndex = 3
	fieldControlRelayToAddr         = 6
	fieldControlRelayFromAddr       = 7
)

// controlType is the NebulaControl message kind.
type controlType uint8

const (
	controlNone                controlType = 0
	controlCreateRelayRequest  controlType = 1
	controlCreateRelayResponse controlType = 2
)

// relayType says which side of a relay an entry describes.
type relayType uint8

const (
	// relayForwarding is the middle host's view: packets arriving on this
	// entry are forwarded to peerAddr rather than decrypted.
	relayForwarding relayType = iota
	// relayTerminal is an end host's view: packets arriving on this entry are
	// unwrapped and processed as though they had come directly.
	relayTerminal
)

// relayState tracks how far a relay's negotiation has got.
type relayState uint8

const (
	// relayRequested: we asked, and have not been answered.
	relayRequested relayState = iota
	// relayPeerRequested: the far end asked us to be its relay, and we are
	// waiting on the other half before we will forward anything.
	relayPeerRequested
	// relayEstablished: usable.
	relayEstablished
)

// relay is one entry in a host's relay table.
//
// The two addresses are the thing to get right, and naming them badly is how
// the middle host's logic goes wrong:
//
//	               A ──────── R ──────── B
//	on A:  {neighbour: R, peer: B, terminal}
//	on R:  {neighbour: A, peer: B, forwarding}   <- packets from A go to B
//	       {neighbour: B, peer: A, forwarding}   <- packets from B go to A
//	on B:  {neighbour: R, peer: A, terminal}
//
// **neighbour** is who is on the other end of *this hop*, and therefore whose
// tunnel keys authenticate it. **peer** is the far end of the whole relayed
// path, which on the middle host is where an arriving packet is forwarded to.
// R's two entries are mirrors of each other, and forwarding is exactly the act
// of looking one up from the other.
type relay struct {
	// localIndex is what we put in a CreateRelayRequest and what our neighbour
	// will address relayed packets to. It is the demux key on the way in.
	localIndex uint32
	// remoteIndex is the neighbour's index, which we address outbound relayed
	// packets to. Zero until the negotiation completes.
	remoteIndex uint32

	// neighbour is the host this hop is with: the relay itself on a terminal
	// entry, or the host whose traffic we forward on a forwarding entry.
	neighbour netip.Addr
	// peerAddr is the far end of the relayed path.
	peerAddr netip.Addr

	typ   relayType
	state relayState
}

var (
	errNoRelay        = errors.New("nebula: no usable relay")
	errRelayLoop      = errors.New("nebula: refusing to relay to myself")
	errRelayNotAsked  = errors.New("nebula: relay response for a request never made")
	errBadControlType = errors.New("nebula: unknown control message type")
)

// relayTable is a host's relay entries, indexed both ways because both lookups
// happen on the data path: by local index when a relayed packet arrives, and
// by peer address when one is about to be sent.
type relayTable struct {
	mu sync.RWMutex
	// byIndex maps our own local index to the entry, for inbound demux.
	byIndex map[uint32]*relay
	// byPeer maps a (relay host, far end) pair to the entry. Two keys rather
	// than one because a host may be reachable through more than one relay,
	// and because the middle host holds two entries whose far ends differ.
	byPeer map[relayKey]*relay
}

// relayKey identifies an entry by the pair it connects: the hop's neighbour
// and the path's far end. Both are needed -- the middle host holds two entries
// whose far ends differ, and an end host may reach one peer through more than
// one relay.
type relayKey struct {
	neighbour netip.Addr
	peer      netip.Addr
}

func newRelayTable() *relayTable {
	return &relayTable{
		byIndex: map[uint32]*relay{},
		byPeer:  map[relayKey]*relay{},
	}
}

// add records a relay, replacing any entry for the same pair. Replacing rather
// than rejecting is deliberate: a peer that reconnects renegotiates its relay,
// and keeping the stale entry would send its traffic to an index the relay has
// already forgotten.
func (rt *relayTable) add(r *relay) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	key := relayKey{neighbour: r.neighbour, peer: r.peerAddr}
	if old, ok := rt.byPeer[key]; ok {
		delete(rt.byIndex, old.localIndex)
	}
	rt.byIndex[r.localIndex] = r
	rt.byPeer[key] = r
}

// byLocalIndex resolves an arriving relayed packet's outer index.
func (rt *relayTable) byLocalIndex(idx uint32) (*relay, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	r, ok := rt.byIndex[idx]
	return r, ok
}

// lookup finds the entry for one hop-and-far-end pair.
func (rt *relayTable) lookup(neighbour, peer netip.Addr) (*relay, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	r, ok := rt.byPeer[relayKey{neighbour: neighbour, peer: peer}]
	return r, ok
}

// mirror returns the entry that carries the other direction of a relayed path,
// which is the forwarding lookup the middle host does on every packet: a
// packet that arrived from `r.neighbour` bound for `r.peerAddr` leaves on the
// entry whose neighbour is `r.peerAddr` and whose far end is `r.neighbour`.
func (rt *relayTable) mirror(r *relay) (*relay, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	m, ok := rt.byPeer[relayKey{neighbour: r.peerAddr, peer: r.neighbour}]
	if !ok || m.typ != relayForwarding {
		return nil, false
	}
	return m, true
}

// terminalFor returns an established terminal relay reaching peer, through any
// relay host. The first usable one wins; the reference does the same, and
// preferring one relay over another needs a signal neither implementation has.
func (rt *relayTable) terminalFor(peer netip.Addr) (*relay, bool) {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, r := range rt.byPeer {
		if r.peerAddr == peer && r.typ == relayTerminal && r.state == relayEstablished {
			return r, true
		}
	}
	return nil, false
}

// setEstablished completes a negotiation under the table's lock, so a data-path
// reader never sees a half-updated entry.
func (rt *relayTable) setEstablished(r *relay, remoteIndex uint32) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	r.remoteIndex = remoteIndex
	r.state = relayEstablished
}

// forget drops every entry that touches a host, in either position.
//
// Called when a tunnel expires. Both positions matter and dropping only one is
// a leak that also misbehaves: an entry whose *neighbour* has gone can never
// be authenticated again, and an entry whose *far end* has gone would go on
// being offered to the data path as an established relay to a host that is not
// there. Either way the negotiation has to happen again, and a stale index is
// what stops it -- add() would find the old key and reuse an index the peer
// has already forgotten.
func (rt *relayTable) forget(host netip.Addr) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for key, r := range rt.byPeer {
		if key.neighbour != host && key.peer != host {
			continue
		}
		delete(rt.byIndex, r.localIndex)
		delete(rt.byPeer, key)
	}
}

// controlMessage is a decoded NebulaControl.
type controlMessage struct {
	Type                controlType
	InitiatorRelayIndex uint32
	ResponderRelayIndex uint32
	// RelayToAddr is the host the relay should forward toward; RelayFromAddr
	// is the host that asked. Both are overlay addresses.
	RelayToAddr   netip.Addr
	RelayFromAddr netip.Addr
}

func (m controlMessage) marshal() []byte {
	var b []byte
	if m.Type != controlNone {
		b = appendUvarintField(b, fieldControlType, uint64(m.Type))
	}
	if m.InitiatorRelayIndex != 0 {
		b = appendUvarintField(b, fieldControlInitiatorRelayIndex, uint64(m.InitiatorRelayIndex))
	}
	if m.ResponderRelayIndex != 0 {
		b = appendUvarintField(b, fieldControlResponderRelayIndex, uint64(m.ResponderRelayIndex))
	}
	if m.RelayToAddr.IsValid() {
		b = appendBytes(b, fieldControlRelayToAddr, marshalProtoAddr(m.RelayToAddr))
	}
	if m.RelayFromAddr.IsValid() {
		b = appendBytes(b, fieldControlRelayFromAddr, marshalProtoAddr(m.RelayFromAddr))
	}
	return b
}

func parseControl(b []byte) (controlMessage, error) {
	var m controlMessage
	for len(b) > 0 {
		field, wire, rest, err := consumeTag(b)
		if err != nil {
			return controlMessage{}, err
		}
		b = rest

		switch {
		case field == fieldControlType && wire == wireVarint:
			v, r, err := consumeVarint(b)
			if err != nil {
				return controlMessage{}, err
			}
			m.Type, b = controlType(v), r
		case field == fieldControlInitiatorRelayIndex && wire == wireVarint:
			v, r, err := consumeVarint(b)
			if err != nil {
				return controlMessage{}, err
			}
			m.InitiatorRelayIndex, b = uint32(v), r
		case field == fieldControlResponderRelayIndex && wire == wireVarint:
			v, r, err := consumeVarint(b)
			if err != nil {
				return controlMessage{}, err
			}
			m.ResponderRelayIndex, b = uint32(v), r
		case field == fieldControlRelayToAddr && wire == wireBytes:
			body, r, err := consumeBytes(b)
			if err != nil {
				return controlMessage{}, err
			}
			if m.RelayToAddr, err = parseProtoAddr(body); err != nil {
				return controlMessage{}, err
			}
			b = r
		case field == fieldControlRelayFromAddr && wire == wireBytes:
			body, r, err := consumeBytes(b)
			if err != nil {
				return controlMessage{}, err
			}
			if m.RelayFromAddr, err = parseProtoAddr(body); err != nil {
				return controlMessage{}, err
			}
			b = r
		default:
			// Unknown fields are skipped, not rejected: the reference sends
			// deprecated IPv4-only address fields to older peers and may add
			// more, and a parser that refused them would break on an upgrade.
			if b, err = skipField(wire, b); err != nil {
				return controlMessage{}, err
			}
		}
	}
	if m.Type != controlCreateRelayRequest && m.Type != controlCreateRelayResponse {
		return controlMessage{}, fmt.Errorf("%w: %d", errBadControlType, m.Type)
	}
	// Both addresses are required in both directions. The reference asserts
	// the same thing and its own tests enumerate the four ways to omit one --
	// an entry built from a zero address would be indexed under the invalid
	// address and never found again.
	if !m.RelayFromAddr.IsValid() {
		return controlMessage{}, errors.New("nebula: control message with no RelayFromAddr")
	}
	if !m.RelayToAddr.IsValid() {
		return controlMessage{}, errors.New("nebula: control message with no RelayToAddr")
	}
	return m, nil
}
