package nebula

// Lighthouses: how hosts find each other.
//
// A mesh has no concentrator, so a host that wants to reach 10.42.0.9 has to
// discover which underlay address that host is currently at. Lighthouses are
// ordinary mesh members that keep a directory: every host tells its lighthouses
// where it is, and asks them where others are.
//
// The messages ride inside established tunnels, so a lighthouse only answers
// hosts whose certificates verified against the same CA. The directory is not
// public, and a query cannot be used to enumerate the mesh from outside it.
//
// This implementation covers the query path and enough of the punch path for
// two hosts behind NAT to meet: when a lighthouse is asked where a host is, it
// both answers the asker and tells the target to send a packet outward. Neither
// packet needs to arrive for a tunnel to form — their purpose is to open the
// NAT bindings so the real handshake can cross.
//
// Relays -- forwarding through a third host when hole punching fails -- are in
// relay.go, and the lighthouse's part in them is here: a host advertises which
// relays will carry for it (RelayVpnAddrs), and a query reply hands that list
// back alongside the underlay addresses.
//
// Not implemented: multi-lighthouse consensus. Two lighthouses that disagree
// about where a host is are not reconciled; the last answer wins. Additive.

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// Field numbers for NebulaMeta.
const (
	fieldMetaType    = 1
	fieldMetaDetails = 2
)

// Field numbers for NebulaMetaDetails. 1 and 5 are deprecated IPv4-only forms
// that this implementation neither sends nor reads.
const (
	fieldDetailsV4AddrPorts = 2
	fieldDetailsCounter     = 3
	fieldDetailsVpnAddr     = 6
	// fieldDetailsRelayVpnAddrs is the list of hosts a peer is willing to be
	// reached through. A lighthouse stores it beside the underlay addresses
	// and hands it back on a query, so a host that cannot reach a peer
	// directly learns who to ask to relay. See relay.go.
	fieldDetailsRelayVpnAddrs = 7
)

// Field numbers for Addr and V4AddrPort.
const (
	fieldAddrHi = 1
	fieldAddrLo = 2

	fieldV4Addr = 1
	fieldV4Port = 2
)

// metaType is the lighthouse message kind.
type metaType uint8

const (
	metaNone                   metaType = 0
	metaHostQuery              metaType = 1
	metaHostQueryReply         metaType = 2
	metaHostUpdateNotification metaType = 3
	metaHostMovedNotification  metaType = 4
	metaHostPunchNotification  metaType = 5
	metaHostWhoami             metaType = 6
	metaHostWhoamiReply        metaType = 7
)

// lighthouseUpdateInterval is how often a host reports where it is.
const lighthouseUpdateInterval = 60 * time.Second

// metaMessage is a decoded lighthouse message.
type metaMessage struct {
	Type metaType
	// VpnAddr is the overlay address the message is about.
	VpnAddr netip.Addr
	// AddrPorts are underlay addresses for that host.
	AddrPorts []netip.AddrPort
	// RelayVpnAddrs are overlay addresses of hosts that will relay for it.
	RelayVpnAddrs []netip.Addr
	Counter       uint32
}

// maxAdvertisedRelays bounds how many relays one host may claim. The reference
// has no explicit limit; this one exists because the list is parsed from a
// peer's message before anything about the peer has been acted on.
const maxAdvertisedRelays = 16

func (m metaMessage) marshal() []byte {
	var details []byte
	for _, ap := range m.AddrPorts {
		if !ap.Addr().Is4() {
			continue
		}
		a := ap.Addr().As4()
		var v4 []byte
		v4 = appendUvarintField(v4, fieldV4Addr, uint64(binary.BigEndian.Uint32(a[:])))
		v4 = appendUvarintField(v4, fieldV4Port, uint64(ap.Port()))
		details = appendBytes(details, fieldDetailsV4AddrPorts, v4)
	}
	if m.Counter != 0 {
		details = appendUvarintField(details, fieldDetailsCounter, uint64(m.Counter))
	}
	if m.VpnAddr.IsValid() {
		details = appendBytes(details, fieldDetailsVpnAddr, marshalProtoAddr(m.VpnAddr))
	}
	for _, r := range m.RelayVpnAddrs {
		details = appendBytes(details, fieldDetailsRelayVpnAddrs, marshalProtoAddr(r))
	}

	var out []byte
	if m.Type != metaNone {
		out = appendUvarintField(out, fieldMetaType, uint64(m.Type))
	}
	return appendBytes(out, fieldMetaDetails, details)
}

func parseMetaMessage(b []byte) (metaMessage, error) {
	var m metaMessage
	for len(b) > 0 {
		field, wire, rest, err := consumeTag(b)
		if err != nil {
			return m, errProto
		}
		b = rest

		switch {
		case field == fieldMetaType && wire == wireVarint:
			v, rest, err := consumeVarint(b)
			if err != nil {
				return m, errProto
			}
			m.Type, b = metaType(v), rest
		case field == fieldMetaDetails && wire == wireBytes:
			body, rest, err := consumeBytes(b)
			if err != nil {
				return m, errProto
			}
			b = rest
			if err := m.parseDetails(body); err != nil {
				return m, err
			}
		default:
			if b, err = skipField(wire, b); err != nil {
				return m, errProto
			}
		}
	}
	return m, nil
}

func (m *metaMessage) parseDetails(b []byte) error {
	for len(b) > 0 {
		field, wire, rest, err := consumeTag(b)
		if err != nil {
			return errProto
		}
		b = rest

		switch field {
		case fieldDetailsV4AddrPorts:
			body, rest, err := bytesField(wire, b)
			if err != nil {
				return errProto
			}
			b = rest
			ap, err := parseV4AddrPort(body)
			if err != nil {
				return err
			}
			m.AddrPorts = append(m.AddrPorts, ap)
		case fieldDetailsVpnAddr:
			body, rest, err := bytesField(wire, b)
			if err != nil {
				return errProto
			}
			b = rest
			addr, err := parseProtoAddr(body)
			if err != nil {
				return err
			}
			m.VpnAddr = addr
		case fieldDetailsRelayVpnAddrs:
			body, rest, err := bytesField(wire, b)
			if err != nil {
				return errProto
			}
			b = rest
			addr, err := parseProtoAddr(body)
			if err != nil {
				return err
			}
			// Bounded: a peer that advertised thousands of relays would make
			// every host that queried it allocate a list of them.
			if len(m.RelayVpnAddrs) < maxAdvertisedRelays {
				m.RelayVpnAddrs = append(m.RelayVpnAddrs, addr)
			}
		case fieldDetailsCounter:
			if wire != wireVarint {
				return errProto
			}
			v, rest, err := consumeVarint(b)
			if err != nil {
				return errProto
			}
			m.Counter, b = uint32(v), rest
		default:
			if b, err = skipField(wire, b); err != nil {
				return errProto
			}
		}
	}
	return nil
}

func parseV4AddrPort(b []byte) (netip.AddrPort, error) {
	var addr, port uint64
	for len(b) > 0 {
		field, wire, rest, err := consumeTag(b)
		if err != nil {
			return netip.AddrPort{}, errProto
		}
		b = rest
		if wire != wireVarint {
			if b, err = skipField(wire, b); err != nil {
				return netip.AddrPort{}, errProto
			}
			continue
		}
		v, rest, err := consumeVarint(b)
		if err != nil {
			return netip.AddrPort{}, errProto
		}
		b = rest
		switch field {
		case fieldV4Addr:
			addr = v
		case fieldV4Port:
			port = v
		}
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(addr))
	return netip.AddrPortFrom(netip.AddrFrom4(raw), uint16(port)), nil
}

// marshalProtoAddr encodes an overlay address as the reference's Addr message.
//
// Addresses are carried as a 128-bit value so the format is the same for IPv4
// and IPv6; an IPv4 address travels in its mapped form. parseProtoAddr unmaps
// on the way back, so a v4 address survives the round trip comparing equal to
// the same address parsed from dotted-quad form -- which is what the host map
// and the relay table key everything on.
func marshalProtoAddr(a netip.Addr) []byte {
	b := a.As16()
	var out []byte
	out = appendUvarintField(out, fieldAddrHi, binary.BigEndian.Uint64(b[:8]))
	return appendUvarintField(out, fieldAddrLo, binary.BigEndian.Uint64(b[8:]))
}

func parseProtoAddr(b []byte) (netip.Addr, error) {
	var hi, lo uint64
	for len(b) > 0 {
		field, wire, rest, err := consumeTag(b)
		if err != nil {
			return netip.Addr{}, errProto
		}
		b = rest
		if wire != wireVarint {
			if b, err = skipField(wire, b); err != nil {
				return netip.Addr{}, errProto
			}
			continue
		}
		v, rest, err := consumeVarint(b)
		if err != nil {
			return netip.Addr{}, errProto
		}
		b = rest
		switch field {
		case fieldAddrHi:
			hi = v
		case fieldAddrLo:
			lo = v
		}
	}
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[:8], hi)
	binary.BigEndian.PutUint64(raw[8:], lo)
	// Unmap so an IPv4 address compares equal to the same address parsed from
	// dotted quad form, which is how the host map keys everything.
	return netip.AddrFrom16(raw).Unmap(), nil
}

// sendMeta delivers a lighthouse message through an established tunnel.
func (h *Host) sendMeta(p *peer, m metaMessage) {
	p.mu.Lock()
	t := p.tun
	p.mu.Unlock()
	if t == nil {
		return
	}
	if err := h.sendToPeer(p, t.encrypt(typeLightHouse, subTypeNone, m.marshal())); err != nil {
		h.log.Printf("nebula: sending lighthouse message to %v: %v", p.addr, err)
	}
}

// queryLighthouses asks where a host is. The reply arrives asynchronously and
// populates the peer's underlay candidates, so the caller does not block: the
// packet that triggered this is lost, and the next one finds a route.
func (h *Host) queryLighthouses(target netip.Addr) {
	for _, lh := range h.lighthouses {
		p, ok := h.lookupPeer(lh)
		if !ok {
			continue
		}
		p.mu.Lock()
		up := p.tun != nil
		p.mu.Unlock()
		if !up {
			// The lighthouse itself needs a tunnel first. Its address is
			// statically configured, so this terminates.
			h.beginHandshake(p)
			continue
		}
		h.sendMeta(p, metaMessage{Type: metaHostQuery, VpnAddr: target})
	}
}

// handleLighthouse processes a lighthouse message from a peer.
func (h *Host) handleLighthouse(pkt []byte, hdr header, from netip.AddrPort) {
	h.mu.RLock()
	t, ok := h.byIndex[hdr.RemoteIndex]
	h.mu.RUnlock()
	if !ok {
		return
	}
	_, payload, err := t.decrypt(pkt)
	if err != nil {
		return
	}
	m, err := parseMetaMessage(payload)
	if err != nil {
		return
	}

	switch m.Type {
	case metaHostQuery:
		h.answerHostQuery(t, m, from)
	case metaHostQueryReply:
		h.learnAddresses(m)
	case metaHostUpdateNotification:
		h.recordUpdate(t, m, from)
	case metaHostPunchNotification:
		h.punch(m)
	case metaHostWhoami:
		h.answerWhoami(t, from)
	case metaHostWhoamiReply:
		// Informational: it tells a host how it appears from outside. Nothing
		// here acts on it yet.
	}
}

// answerHostQuery replies with what this lighthouse knows, and nudges the
// target to punch outward so the two can meet through NAT.
func (h *Host) answerHostQuery(t *tunnel, m metaMessage, asker netip.AddrPort) {
	if !h.cfg.AmLighthouse {
		return
	}
	target, ok := h.lookupPeer(m.VpnAddr)
	if !ok {
		return
	}
	target.mu.Lock()
	addrs := append([]netip.AddrPort(nil), target.underlay...)
	relays := append([]netip.Addr(nil), target.relayVia...)
	target.mu.Unlock()
	if len(addrs) == 0 && len(relays) == 0 {
		return
	}

	if asking, ok := h.lookupPeer(t.PeerAddr()); ok {
		h.sendMeta(asking, metaMessage{
			Type:          metaHostQueryReply,
			VpnAddr:       m.VpnAddr,
			AddrPorts:     addrs,
			RelayVpnAddrs: relays,
		})
	}

	// Tell the target to send something towards the asker. The packet itself
	// is expected to be dropped by the asker's NAT; what matters is that it
	// opens the target's binding so the asker's handshake gets through.
	h.sendMeta(target, metaMessage{
		Type:      metaHostPunchNotification,
		VpnAddr:   t.PeerAddr(),
		AddrPorts: []netip.AddrPort{asker},
	})
}

// learnAddresses records where a lighthouse says a host can be found, and
// starts a handshake now that there is somewhere to send it.
func (h *Host) learnAddresses(m metaMessage) {
	if !m.VpnAddr.IsValid() {
		return
	}
	if len(m.AddrPorts) == 0 && len(m.RelayVpnAddrs) == 0 {
		return
	}
	p := h.peerFor(m.VpnAddr)
	p.mu.Lock()
	p.underlay = mergeAddrs(p.underlay, m.AddrPorts)
	p.relayVia = append([]netip.Addr(nil), m.RelayVpnAddrs...)
	up := p.tun != nil
	direct := len(p.underlay) > 0
	relays := append([]netip.Addr(nil), p.relayVia...)
	p.mu.Unlock()

	if up {
		return
	}
	if direct {
		h.beginHandshake(p)
		return
	}
	// The lighthouse knows of this host but has no address for it -- which is
	// what a peer behind a NAT that never reported one looks like. Its relays
	// are the only way to reach it, so ask them rather than handshaking into
	// nowhere.
	for _, via := range relays {
		if err := h.requestRelay(via, m.VpnAddr); err != nil {
			h.log.Printf("nebula: relay %v for %v: %v", via, m.VpnAddr, err)
		}
	}
}

// recordUpdate stores a host's own report of where it is. Only a lighthouse
// keeps these, and only for the address the reporting peer's certificate
// authorizes -- otherwise any member could redirect traffic for any other.
func (h *Host) recordUpdate(t *tunnel, m metaMessage, from netip.AddrPort) {
	if !h.cfg.AmLighthouse {
		return
	}
	if m.VpnAddr != t.PeerAddr() {
		h.log.Printf("nebula: %v (%s) tried to update the record for %v",
			t.PeerAddr(), t.peerCert.Name, m.VpnAddr)
		return
	}
	p := h.peerFor(m.VpnAddr)
	p.mu.Lock()
	// The address the report arrived from is worth more than the ones inside
	// it: it is observed rather than claimed, and it is what a NATed host looks
	// like from here.
	p.underlay = mergeAddrs([]netip.AddrPort{from}, m.AddrPorts)
	// The relay list, unlike the addresses, can only be claimed -- a
	// lighthouse has no way to observe who will relay for whom. It is stored
	// as given and handed back on a query; what stops it being a redirection
	// primitive is that a host asked to relay decides for itself (RelayFor),
	// and a relay that has not agreed simply never answers.
	p.relayVia = append([]netip.Addr(nil), m.RelayVpnAddrs...)
	p.mu.Unlock()
}

// punch sends a single datagram towards a peer to open this host's NAT binding.
func (h *Host) punch(m metaMessage) {
	for _, ap := range m.AddrPorts {
		// An empty datagram is enough: it is never parsed as a nebula packet
		// by the far side, and its only job is to create the binding.
		if _, err := h.conn.WriteToUDPAddrPort([]byte{}, ap); err != nil {
			h.log.Printf("nebula: punching towards %v: %v", ap, err)
		}
	}
	// The peer that asked for the punch is presumably about to handshake, but
	// starting from this side too makes the meeting happen sooner.
	if m.VpnAddr.IsValid() {
		if p, ok := h.lookupPeer(m.VpnAddr); ok {
			h.beginHandshake(p)
		}
	}
}

// answerWhoami tells a peer how it appears from here.
func (h *Host) answerWhoami(t *tunnel, from netip.AddrPort) {
	if p, ok := h.lookupPeer(t.PeerAddr()); ok {
		h.sendMeta(p, metaMessage{
			Type:      metaHostWhoamiReply,
			VpnAddr:   t.PeerAddr(),
			AddrPorts: []netip.AddrPort{from},
		})
	}
}

// reportToLighthouses tells each lighthouse where this host is.
func (h *Host) reportToLighthouses() {
	for _, lh := range h.lighthouses {
		p, ok := h.lookupPeer(lh)
		if !ok {
			continue
		}
		p.mu.Lock()
		up := p.tun != nil
		p.mu.Unlock()
		if !up {
			h.beginHandshake(p)
			continue
		}
		h.sendMeta(p, metaMessage{
			Type:          metaHostUpdateNotification,
			RelayVpnAddrs: h.relayVia(),
			VpnAddr:       h.addr,
			AddrPorts:     h.localAddrPorts(),
		})
	}
}

// localAddrPorts is what this host believes its own underlay addresses are.
// A NATed host's report is mostly wrong, which is why a lighthouse prefers the
// address it observed; on a directly reachable host it is exactly right.
func (h *Host) localAddrPorts() []netip.AddrPort {
	// *net.UDPAddr provides AddrPort; the in-memory socket used in tests
	// provides it too, so neither needs a special case here.
	if udp, ok := h.conn.LocalAddr().(interface{ AddrPort() netip.AddrPort }); ok {
		if ap := udp.AddrPort(); ap.IsValid() {
			return []netip.AddrPort{ap}
		}
	}
	return nil
}

// mergeAddrs prepends new candidates without duplicating existing ones.
func mergeAddrs(existing, incoming []netip.AddrPort) []netip.AddrPort {
	seen := map[netip.AddrPort]struct{}{}
	out := make([]netip.AddrPort, 0, len(existing)+len(incoming))
	for _, a := range append(append([]netip.AddrPort(nil), incoming...), existing...) {
		if !a.IsValid() {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}
