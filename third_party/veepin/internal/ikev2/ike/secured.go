package ike

import (
	"net"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// handleSecured decrypts and dispatches a protected exchange (everything after
// IKE_SA_INIT).
func (s *Server) handleSecured(pkt []byte, hdr payload.Header, remote *net.UDPAddr, ex payload.ExchangeType, on4500 bool) {
	if hdr.IsResponse() {
		return // pure responder
	}
	sa := s.lookupByRSPI(hdr.ResponderSPI)
	if sa == nil {
		s.log.Printf("ikev2: %s from %s has no IKE SA (rSPI=%#x)", ex, remote, hdr.ResponderSPI)
		return
	}

	sa.mu.Lock()
	defer sa.mu.Unlock()
	sa.touch()

	// Track the peer floating to port 4500 (NAT-T) and any address change so
	// responses and ESP go to the right place.
	if on4500 && !sa.OnPort4500 {
		sa.OnPort4500 = true
	}
	sa.RemoteAddr = remote

	if hdr.MessageID != sa.RecvMsgID {
		s.log.Printf("ikev2: %s from %s bad msgid %d (want %d)", ex, remote, hdr.MessageID, sa.RecvMsgID)
		return
	}

	msg, err := payload.ParseMessage(pkt)
	if err != nil {
		s.log.Printf("ikev2: %s parse from %s: %v", ex, remote, err)
		return
	}
	var firstInner payload.PayloadType
	var inner []byte
	if skfPay := msg.Find(payload.TypeSKF); skfPay != nil {
		// RFC 7383 fragment: decrypt it and hold it until every fragment of this
		// message has arrived. Reassembly proceeds only once, on completion.
		if !sa.fragEnabled {
			s.log.Printf("ikev2: %s from %s sent an SKF fragment without negotiating fragmentation", ex, remote)
			return
		}
		fragNum, total, fi, chunk, derr := decryptSKF(pkt, *skfPay, sa.Suite, sa.Keys, sa.dirForInbound())
		if derr != nil {
			s.log.Warnf("ikev2: %s from %s SKF decrypt failed: %v", ex, remote, derr)
			return
		}
		reasm, rfi, complete, rerr := sa.fragReasm.add(hdr.MessageID, fragNum, total, fi, chunk)
		if rerr != nil {
			s.log.Printf("ikev2: %s from %s fragment reassembly: %v", ex, remote, rerr)
			return
		}
		if !complete {
			return // await the remaining fragments
		}
		inner, firstInner = reasm, rfi
	} else {
		skPay := msg.Find(payload.TypeSK)
		if skPay == nil {
			s.log.Printf("ikev2: %s from %s missing SK payload", ex, remote)
			return
		}
		fi, in, derr := decryptSK(pkt, hdr, *skPay, sa.Suite, sa.Keys, sa.dirForInbound())
		if derr != nil {
			s.log.Warnf("ikev2: %s from %s decrypt failed: %v", ex, remote, derr)
			return
		}
		firstInner, inner = fi, in
	}

	inners, err := parseInnerPayloads(firstInner, inner)
	if err != nil {
		s.log.Printf("ikev2: %s from %s inner parse: %v", ex, remote, err)
		return
	}

	switch ex {
	case payload.IKE_AUTH:
		s.handleIKEAuth(sa, hdr, inners, remote)
	case payload.IKE_INTERMEDIATE:
		s.handleIKEIntermediate(sa, hdr, inners, remote)
	case payload.CREATE_CHILD_SA:
		s.handleCreateChildSA(sa, hdr, inners, remote)
	case payload.INFORMATIONAL:
		s.handleInformational(sa, hdr, inners, remote)
	}
}

// respondEncrypted builds and sends an encrypted response for the given
// request message ID, wrapping the supplied inner payload chain. The response
// is sent on whichever port the SA has floated to.
func (s *Server) respondEncrypted(sa *IKESA, ex payload.ExchangeType, msgID uint32,
	firstInner payload.PayloadType, innerChain []byte, remote *net.UDPAddr) {

	hdr := payload.Header{
		InitiatorSPI: sa.InitiatorSPI,
		ResponderSPI: sa.ResponderSPI,
		ExchangeType: ex,
		Flags:        payload.FlagResponse,
		MessageID:    msgID,
	}
	// sa.fragEnabled records whether the initiator advertised RFC 7383 in
	// IKE_SA_INIT. It gates fragmentation for exactly the same reason the
	// client's c.frag does: a peer that did not advertise support will not
	// reassemble SKF payloads, and sending them to one is a dead handshake.
	pkts, err := sealMaybeFragment(hdr, sa.Suite, sa.Keys, sa.dirForOutbound(),
		firstInner, innerChain, sa.fragEnabled)
	if err != nil {
		s.log.Printf("ikev2: build encrypted %s response: %v", ex, err)
		return
	}
	if len(pkts) > 1 {
		s.log.Printf("ikev2: fragmenting %s response (msgid %d) into %d RFC 7383 fragments", ex, msgID, len(pkts))
	}
	for _, pkt := range pkts {
		s.send(pkt, remote, sa.OnPort4500)
	}
}

// respondEncryptedNotify sends an encrypted response carrying a single Notify.
func (s *Server) respondEncryptedNotify(sa *IKESA, ex payload.ExchangeType, msgID uint32,
	nt payload.NotifyType, remote *net.UDPAddr) {

	b := payload.NewBuilder()
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: nt,
	}))
	s.respondEncrypted(sa, ex, msgID, b.FirstType(), b.Bytes(), remote)
}
