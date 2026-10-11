package ike

import (
	"net"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// MOBIKE (RFC 4555) lets an established IKE SA and its Child SAs survive an
// endpoint changing address — a client roaming between networks — with one
// protected INFORMATIONAL instead of a full re-handshake. Support is a pure
// capability flag (MOBIKE_SUPPORTED, empty payload) exchanged in IKE_AUTH; the
// move itself is an INFORMATIONAL carrying UPDATE_SA_ADDRESSES from the new
// address, and the responder relocates the SA to the *observed* source address
// — never one claimed in a payload, since a NAT may have rewritten it and only
// the observed address is reachable.
//
// This file holds the notify helpers plus the responder's UPDATE_SA_ADDRESSES /
// COOKIE2 handling. The initiator side (sending the update on roam) lives in
// client.go.

// findMobikeSupported reports whether the peer advertised MOBIKE_SUPPORTED.
func findMobikeSupported(inners []payload.RawPayload) bool {
	for _, p := range inners {
		if p.Type != payload.TypeNotify {
			continue
		}
		if n, err := payload.ParseNotify(p.Body); err == nil && n.Type == payload.MobikeSupported {
			return true
		}
	}
	return false
}

// addMobikeSupported appends an empty MOBIKE_SUPPORTED notify to b.
func addMobikeSupported(b *payload.Builder) {
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.MobikeSupported,
	}))
}

// findNotify returns the first notify of the given type among inners, or nil.
func findNotify(inners []payload.RawPayload, t payload.NotifyType) *payload.NotifyPayload {
	for _, p := range inners {
		if p.Type != payload.TypeNotify {
			continue
		}
		if n, err := payload.ParseNotify(p.Body); err == nil && n.Type == t {
			nn := n
			return &nn
		}
	}
	return nil
}

// handleMobikeInformational processes the MOBIKE parts of an INFORMATIONAL
// request, appending any response notifies to b. It returns true if the message
// was a MOBIKE message (so the caller responds even when nothing else matched).
//
// Two notifies matter:
//   - COOKIE2: a return-routability probe. RFC 4555 3.7 requires the recipient
//     to echo it unchanged in the response, which proves to the peer that the
//     same party it addressed is answering from the address it used.
//   - UPDATE_SA_ADDRESSES: relocate the SA. We move it to remote (the observed
//     source), re-run NAT detection from the message's fresh NAT_DETECTION
//     hashes, repoint every Child SA's ESP return address, and echo our own NAT
//     detection so the peer re-evaluates its side.
//
// The caller holds sa.mu.
func (s *Server) handleMobikeInformational(sa *IKESA, inners []payload.RawPayload, remote *net.UDPAddr, b *payload.Builder) bool {
	cookie2 := findNotify(inners, payload.Cookie2)
	update := findNotify(inners, payload.UpdateSAAddresses)
	if cookie2 == nil && update == nil {
		return false
	}

	// Echo COOKIE2 verbatim (RFC 4555 3.7). Do this even when we reject the
	// update below, so a bare return-routability probe still works.
	if cookie2 != nil {
		b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
			Protocol: payload.ProtoNone, Type: payload.Cookie2, Data: cookie2.Data,
		}))
	}

	if update == nil {
		return true
	}
	if !sa.MobikeEnabled {
		// The peer tried to move without negotiating MOBIKE. Ignore the move but
		// still return a (COOKIE2-echoing) response so the exchange completes.
		s.log.Printf("ikev2: UPDATE_SA_ADDRESSES from %s on a non-MOBIKE SA, ignored", remote)
		return true
	}

	// Relocate to the observed source address. handleSecured already set
	// sa.RemoteAddr and maintained sa.OnPort4500 for this packet.
	sa.RemoteAddr = remote
	sa.NAT = s.detectNAT(inners, sa.InitiatorSPI, sa.ResponderSPI, remote, sa.OnPort4500)

	udpEncap := sa.NAT.natDetected() || sa.OnPort4500
	for _, c := range sa.Children {
		c.PeerAddr = remote
		c.UDPEncap = udpEncap
	}
	// Push the new return address into the data path immediately, rather than
	// waiting for the first inbound ESP from the new address to move it.
	if up, ok := s.cfg.DataPath.(peerAddrUpdater); ok {
		up.UpdatePeerAddr(sa, remote)
	}

	// Our NAT detection, so the peer re-evaluates its own NAT status too.
	s.addNATDetection(b, sa.InitiatorSPI, sa.ResponderSPI, remote, sa.OnPort4500)

	s.log.Printf("ikev2: MOBIKE UPDATE_SA_ADDRESSES: SA %#x moved to %s", sa.ResponderSPI, remote)
	return true
}
