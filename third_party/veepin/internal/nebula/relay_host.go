package nebula

// The host-side half of relays: negotiating them, forwarding through them, and
// deciding when to reach for one. The wire format, the entry model and the
// vocabulary are in relay.go.

import (
	"fmt"
	"net/netip"
)

// sendControl delivers a NebulaControl message through an established tunnel.
func (h *Host) sendControl(p *peer, m controlMessage) {
	p.mu.Lock()
	t := p.tun
	p.mu.Unlock()
	if t == nil {
		return
	}
	if err := h.sendToPeer(p, t.encrypt(typeControl, subTypeNone, m.marshal())); err != nil {
		h.log.Printf("nebula: sending control message to %v: %v", p.addr, err)
	}
}

// requestRelay asks via to relay this host's traffic to target.
//
// It is safe to call repeatedly: an entry already in flight is left alone
// rather than renegotiated, so a burst of packets to an unreachable peer
// produces one request rather than one per packet.
func (h *Host) requestRelay(via, target netip.Addr) error {
	if via == target || via == h.addr || target == h.addr {
		return errRelayLoop
	}
	if _, ok := h.relays.lookup(via, target); ok {
		return nil // already asked, or already established
	}

	viaPeer, ok := h.lookupPeer(via)
	if !ok {
		return fmt.Errorf("%w: relay %v is not a known peer", errNoRelay, via)
	}
	viaPeer.mu.Lock()
	up := viaPeer.tun != nil
	viaPeer.mu.Unlock()
	if !up {
		// The relay itself has to be reachable directly. Relaying through a
		// relay is not something either implementation does, and allowing it
		// would make a forwarding loop expressible.
		h.beginHandshake(viaPeer)
		return fmt.Errorf("%w: no tunnel to relay %v yet", errNoRelay, via)
	}

	idx, err := newLocalIndex()
	if err != nil {
		return err
	}
	h.relays.add(&relay{
		localIndex: idx,
		neighbour:  via,
		peerAddr:   target,
		typ:        relayTerminal,
		state:      relayRequested,
	})

	h.log.Printf("nebula: asking %v to relay for %v", via, target)
	h.sendControl(viaPeer, controlMessage{
		Type:                controlCreateRelayRequest,
		InitiatorRelayIndex: idx,
		RelayFromAddr:       h.addr,
		RelayToAddr:         target,
	})
	return nil
}

// resendRelayRequest repeats an outstanding CreateRelayRequest. Control
// messages carry no retransmission of their own, and the relay has no way to
// discover that we are still waiting.
func (h *Host) resendRelayRequest(via netip.Addr, r *relay) {
	p, ok := h.lookupPeer(via)
	if !ok {
		return
	}
	h.sendControl(p, controlMessage{
		Type:                controlCreateRelayRequest,
		InitiatorRelayIndex: r.localIndex,
		RelayFromAddr:       h.addr,
		RelayToAddr:         r.peerAddr,
	})
}

// handleControl processes a NebulaControl message arriving on a tunnel.
func (h *Host) handleControl(pkt []byte, hdr header, _ netip.AddrPort) {
	t, ok := h.tunnelFor(hdr.RemoteIndex)
	if !ok {
		return
	}
	_, payload, err := t.decrypt(pkt)
	if err != nil {
		return
	}
	m, err := parseControl(payload)
	if err != nil {
		h.log.Printf("nebula: bad control message from %v: %v", t.peerAddr, err)
		return
	}

	switch m.Type {
	case controlCreateRelayRequest:
		// A request may legitimately arrive from the host it names (A asking
		// its relay) or from a relay propagating on that host's behalf (R
		// asking B). What must never be accepted is a request from a host that
		// is neither end and is not a relay we would use -- so the sender is
		// taken from the tunnel and checked against the message.
		if m.RelayFromAddr != t.peerAddr && m.RelayToAddr != h.addr {
			h.log.Printf("nebula: %v sent a relay request for %v->%v it is not part of",
				t.peerAddr, m.RelayFromAddr, m.RelayToAddr)
			return
		}
		h.handleRelayRequest(t.peerAddr, m)
	case controlCreateRelayResponse:
		h.handleRelayResponse(t.peerAddr, m)
	}
}

// handleRelayRequest handles a CreateRelayRequest, in either of the two roles
// that can receive one.
//
// The three-party negotiation is worth spelling out, because the middle host
// does not merely agree -- it **propagates**. A asks R to relay to B, and B
// has never heard of the arrangement, so R asks B on A's behalf:
//
//	A --CreateRelayRequest{A->B}--> R
//	                                R --CreateRelayRequest{A->B}--> B
//	                                R <--CreateRelayResponse------- B
//	A <--CreateRelayResponse------- R
//
// Only when B has answered does R's half toward B leave PeerRequested, and
// only then will R forward anything. That ordering is the whole of what stops
// a relay being an amplifier: a host that never agreed to be relayed to never
// receives a packet through one.
//
// The first shape this took had R create a PeerRequested half and wait for B
// to ask independently. B has no reason to ask -- it is not the one sending --
// so the negotiation completed on A's side, R agreed, and every packet was
// then dropped at R by the mirror check. The relay looked established from
// both ends it was visible from.
func (h *Host) handleRelayRequest(sender netip.Addr, m controlMessage) {
	if m.RelayToAddr == h.addr {
		h.acceptRelayToMe(sender, m)
		return
	}
	if !h.cfg.RelayFor {
		// Not a relay. Silence rather than a refusal: the reference has no
		// "no" to send, and a requester that gets no response goes on trying
		// the direct path, which is the right outcome.
		return
	}
	if m.RelayFromAddr == m.RelayToAddr || m.RelayFromAddr == h.addr {
		return
	}

	// The half toward the requester. Packets arriving on this index came from
	// the requester and are bound for the target.
	if _, ok := h.relays.lookup(m.RelayFromAddr, m.RelayToAddr); !ok {
		idx, err := newLocalIndex()
		if err != nil {
			return
		}
		h.relays.add(&relay{
			localIndex:  idx,
			remoteIndex: m.InitiatorRelayIndex,
			neighbour:   m.RelayFromAddr,
			peerAddr:    m.RelayToAddr,
			typ:         relayForwarding,
			state:       relayPeerRequested,
		})
	}

	// The half toward the target, and the request that asks the target to
	// agree to it. Only a peer we already hold a tunnel with can be asked --
	// relaying through a relay is not something either implementation does.
	target, ok := h.lookupPeer(m.RelayToAddr)
	if !ok {
		return
	}
	target.mu.Lock()
	up := target.tun != nil
	target.mu.Unlock()
	if !up {
		// Build the tunnel now so a later request finds it ready.
		h.beginHandshake(target)
		return
	}

	toTarget, ok := h.relays.lookup(m.RelayToAddr, m.RelayFromAddr)
	if !ok {
		idx, err := newLocalIndex()
		if err != nil {
			return
		}
		toTarget = &relay{
			localIndex: idx,
			neighbour:  m.RelayToAddr,
			peerAddr:   m.RelayFromAddr,
			typ:        relayForwarding,
			state:      relayRequested,
		}
		h.relays.add(toTarget)
	}

	h.log.Printf("nebula: relaying for %v to %v", m.RelayFromAddr, m.RelayToAddr)
	h.sendControl(target, controlMessage{
		Type:                controlCreateRelayRequest,
		InitiatorRelayIndex: toTarget.localIndex,
		RelayFromAddr:       m.RelayFromAddr,
		RelayToAddr:         m.RelayToAddr,
	})
}

// acceptRelayToMe is the far end's side: a relay is offering to carry traffic
// for us from some other host.
func (h *Host) acceptRelayToMe(sender netip.Addr, m controlMessage) {
	r, ok := h.relays.lookup(sender, m.RelayFromAddr)
	if !ok {
		idx, err := newLocalIndex()
		if err != nil {
			return
		}
		r = &relay{
			localIndex:  idx,
			remoteIndex: m.InitiatorRelayIndex,
			neighbour:   sender,
			peerAddr:    m.RelayFromAddr,
			typ:         relayTerminal,
			state:       relayEstablished,
		}
		h.relays.add(r)
		h.log.Printf("nebula: reachable from %v via relay %v", m.RelayFromAddr, sender)
	} else {
		h.relays.setEstablished(r, m.InitiatorRelayIndex)
	}

	p, ok := h.lookupPeer(sender)
	if !ok {
		return
	}
	h.sendControl(p, controlMessage{
		Type:                controlCreateRelayResponse,
		InitiatorRelayIndex: r.remoteIndex,
		ResponderRelayIndex: r.localIndex,
		RelayFromAddr:       m.RelayFromAddr,
		RelayToAddr:         m.RelayToAddr,
	})
}

// handleRelayResponse completes a negotiation, in either of the two roles that
// can receive one: the host that asked, or the relay that asked on its behalf.
func (h *Host) handleRelayResponse(sender netip.Addr, m controlMessage) {
	if m.RelayFromAddr == h.addr {
		// We asked. The entry is the terminal one through this relay.
		r, ok := h.relays.lookup(sender, m.RelayToAddr)
		if !ok {
			h.log.Printf("nebula: %v", errRelayNotAsked)
			return
		}
		if r.localIndex != m.InitiatorRelayIndex {
			// The response names an index we did not ask with. Dropping it
			// keeps a third party from completing a relay we never started.
			return
		}
		h.relays.setEstablished(r, m.ResponderRelayIndex)
		h.log.Printf("nebula: relay established via %v for %v", sender, m.RelayToAddr)
		return
	}

	// We are the relay, and the target has agreed. Establish our half toward
	// it, then tell the host that asked.
	toTarget, ok := h.relays.lookup(sender, m.RelayFromAddr)
	if !ok || toTarget.typ != relayForwarding {
		return
	}
	h.relays.setEstablished(toTarget, m.ResponderRelayIndex)

	back, ok := h.relays.lookup(m.RelayFromAddr, m.RelayToAddr)
	if !ok {
		return
	}
	h.relays.setEstablished(back, back.remoteIndex)
	h.log.Printf("nebula: relay ready between %v and %v", m.RelayFromAddr, m.RelayToAddr)

	p, ok := h.lookupPeer(m.RelayFromAddr)
	if !ok {
		return
	}
	h.sendControl(p, controlMessage{
		Type:                controlCreateRelayResponse,
		InitiatorRelayIndex: back.remoteIndex,
		ResponderRelayIndex: back.localIndex,
		RelayFromAddr:       m.RelayFromAddr,
		RelayToAddr:         m.RelayToAddr,
	})
}

// sendRelayed wraps an already-encrypted packet for the far end and sends it to
// this hop's neighbour.
func (h *Host) sendRelayed(r *relay, inner []byte) error {
	p, ok := h.lookupPeer(r.neighbour)
	if !ok {
		return fmt.Errorf("%w: relay neighbour %v is unknown", errNoRelay, r.neighbour)
	}
	p.mu.Lock()
	t := p.tun
	p.mu.Unlock()
	if t == nil {
		return fmt.Errorf("%w: no tunnel to %v", errNoRelay, r.neighbour)
	}

	// sealRelay stamps the tunnel's own remote index; a relayed packet is
	// demultiplexed on the relay index instead, so it is overwritten before
	// the tag is computed over the header.
	out := t.sealRelayTo(r.remoteIndex, inner)
	return h.sendToPeer(p, out)
}

// handleRelayMessage processes a Message/Relay packet: either we are the relay
// and must forward it, or we are its destination and must unwrap it.
func (h *Host) handleRelayMessage(pkt []byte, hdr header, from netip.AddrPort) {
	r, ok := h.relays.byLocalIndex(hdr.RemoteIndex)
	if !ok {
		return
	}

	// The hop is authenticated by the neighbour's tunnel, which is what makes
	// the relay index safe to trust: an index alone is a guessable 32-bit
	// number, and the tag over it is not.
	p, ok := h.lookupPeer(r.neighbour)
	if !ok {
		return
	}
	p.mu.Lock()
	t := p.tun
	p.mu.Unlock()
	if t == nil {
		return
	}

	_, inner, err := t.openRelay(pkt)
	if err != nil {
		return
	}

	switch r.typ {
	case relayTerminal:
		innerHdr, err := parseHeader(inner)
		if err != nil {
			return
		}
		if innerHdr.Subtype == subTypeRelay {
			// A relayed packet that is itself relayed would be a forwarding
			// loop. Neither implementation builds one, and refusing it here
			// means a malicious peer cannot either.
			return
		}

		// Make sure there is a relay back the way this came. The far end
		// reached us through this relay, so our replies have to go the same
		// way -- and until we have asked the relay ourselves it holds only the
		// half of the pair that carries traffic towards us.
		//
		// Without this the handshake completes in one direction and hangs: the
		// initiator's message arrives, the responder answers to the relay's
		// underlay address as an ordinary packet, and the relay drops it
		// because nothing addresses one of its relay indices.
		if _, ok := h.relays.lookup(r.neighbour, r.peerAddr); !ok {
			if err := h.requestRelay(r.neighbour, r.peerAddr); err != nil {
				h.log.Printf("nebula: return relay via %v for %v: %v", r.neighbour, r.peerAddr, err)
			}
		}

		// Process as though it had arrived directly, with `from` left as the
		// relay's underlay address: rewriting it would corrupt roaming, and a
		// reply is routed by the relay table rather than by this value.
		switch innerHdr.Type {
		case typeMessage:
			h.handleMessage(inner, innerHdr, from)
		case typeHandshake:
			h.handleHandshake(append([]byte(nil), inner...), innerHdr, from)
		case typeLightHouse:
			h.handleLighthouse(append([]byte(nil), inner...), innerHdr, from)
		case typeControl:
			h.handleControl(append([]byte(nil), inner...), innerHdr, from)
		}

	case relayForwarding:
		mirror, ok := h.relays.mirror(r)
		if !ok || mirror.state != relayEstablished {
			return
		}
		if err := h.sendRelayed(mirror, inner); err != nil {
			h.log.Printf("nebula: forwarding to %v: %v", mirror.neighbour, err)
		}
	}
}

// relayVia returns the overlay addresses this host is willing to be reached
// through, for advertisement to a lighthouse.
func (h *Host) relayVia() []netip.Addr {
	return append([]netip.Addr(nil), h.cfg.Relays...)
}
