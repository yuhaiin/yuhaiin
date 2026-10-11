package ike

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/xen0bit/veepin/internal/ikev2/aggfrag"
	"github.com/xen0bit/veepin/internal/ikev2/eap"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// handleIKEAuth processes an IKE_AUTH request. Two authentication modes are
// supported:
//
//   - PSK: the initiator includes an AUTH payload; we verify it and respond
//     with our AUTH plus the Child SA in a single round trip.
//   - EAP (username/password): the initiator omits AUTH (RFC 7296 2.16). We
//     respond with our own AUTH (PSK, server-side) plus the first EAP request,
//     then exchange EAP messages over further IKE_AUTH round trips, and finally
//     verify the initiator's AUTH computed from the EAP MSK before creating the
//     Child SA.
func (s *Server) handleIKEAuth(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	// Are we mid-EAP already? Then this request carries an EAP response (or the
	// final AUTH).
	if sa.eapServer != nil {
		s.handleEAPContinue(sa, hdr, inners, remote)
		return
	}
	sa.IKEAuthMsgID = hdr.MessageID

	authPay := findInner(inners, payload.TypeAUTH)
	idiPay := findInner(inners, payload.TypeIDi)
	if idiPay == nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	idi, err := payload.ParseID(idiPay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}
	sa.PeerID = idi
	sa.IDiForAuth = idPayloadBody(Identity{Type: idi.Type, Data: idi.Data})
	sa.peerMobike = findMobikeSupported(inners)

	// No AUTH payload → the client wants EAP.
	if authPay == nil {
		if s.cfg.RequirePostQuantumAuth {
			// Not a quantum argument: EAP-MSCHAPv2's own primitives are MD4 and
			// single-DES, broken classically. A name promising maximum assurance
			// should not accept it. PSK, which is also symmetric, IS accepted --
			// see Config.RequirePostQuantumAuth.
			s.log.Warnf("ikev2: refusing EAP from %s: this server requires post-quantum "+
				"authentication and EAP-MSCHAPv2 is keyed by MD4 and single-DES", remote)
			s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
			return
		}
		if s.cfg.EAPCredentials == nil {
			s.log.Printf("ikev2: %s requested EAP but server has no credentials", remote)
			s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
			return
		}
		s.handleEAPStart(sa, hdr, inners, remote)
		return
	}

	auth, err := payload.ParseAuth(authPay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}

	// Certificate path (RFC 7427 Digital Signature, or legacy RSA): the client
	// signs its AUTH rather than MACing it, and presents a certificate chain.
	if auth.Method == payload.AuthDigitalSig || auth.Method == payload.AuthRSASig {
		if s.cfg.RequirePostQuantumAuth && auth.Method == payload.AuthRSASig {
			// Method 1 is RSASSA-PKCS1-v1_5 over SHA-1 and names no algorithm,
			// so there is no post-quantum spelling of it to accept.
			s.log.Warnf("ikev2: refusing %s: legacy RSA AUTH (method 1) cannot be post-quantum", remote)
			s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
			return
		}
		s.handleCertAuth(sa, hdr, inners, auth, remote)
		return
	}

	// PSK path (single round trip).
	if auth.Method != payload.AuthSharedKeyMIC {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	if err := verifyPeerPSKAuth(sa.Suite.PRF, s.cfg.PSK,
		sa.InitiatorSAInit, sa.Nr, sa.Keys.SKpi, sa.IDiForAuth,
		sa.intAuth(sa.IKEAuthMsgID), auth.Data); err != nil {
		s.log.Warnf("ikev2: IKE_AUTH (PSK) from %s failed: %v", remote, err)
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}

	// Build our AUTH (PSK) and finish with the Child SA in one response.
	localIDBody := idPayloadBody(s.cfg.LocalID)
	ourAuth := computePSKAuth(sa.Suite.PRF, s.cfg.PSK, sa.ResponderSAInit, sa.Ni, sa.Keys.SKpr, localIDBody, sa.intAuth(sa.IKEAuthMsgID))

	b := payload.NewBuilder()
	b.Add(payload.TypeIDr, false, localIDBody)
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: ourAuth,
	}))
	s.finishIKEAuth(sa, hdr, inners, b, remote)
}

// handleCertAuth verifies a certificate-authenticated initiator and responds in
// kind. The client presented IDi, a certificate chain and a signed AUTH; we
// chain-verify the certificate to ClientCAs, bind it to IDi, verify the
// signature over the initiator's signed octets, then sign our own AUTH with the
// server certificate and return it with our chain and the Child SA.
func (s *Server) handleCertAuth(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, auth payload.AuthPayload, remote *net.UDPAddr) {
	if s.cfg.ClientCAs == nil || s.serverCred == nil {
		s.log.Printf("ikev2: %s offered certificate auth but the server is not configured for it", remote)
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}

	certs := findAllInner(inners, payload.TypeCERT)
	if len(certs) == 0 {
		s.log.Printf("ikev2: %s certificate auth with no CERT payload", remote)
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	leafDER, intermediates, perr := parseCertChain(certs)
	if perr != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	leaf, err := verifyPeerCertChain(leafDER, intermediates, s.cfg.ClientCAs)
	if err != nil {
		s.log.Warnf("ikev2: %s certificate chain rejected: %v", remote, err)
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	if err := certMatchesID(leaf, sa.PeerID); err != nil {
		s.log.Printf("ikev2: %s certificate/identity mismatch: %v", remote, err)
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}

	// The initiator signs InitiatorSAInit | {Intermediate} | Nr | prf(SK_pi, IDi').
	octets := AuthOctets(sa.Suite.PRF, sa.InitiatorSAInit, sa.Nr, sa.Keys.SKpi, sa.IDiForAuth, sa.intAuth(sa.IKEAuthMsgID))
	if s.cfg.RequirePostQuantumAuth {
		if err := requirePostQuantumKey(leaf.PublicKey); err != nil {
			s.log.Warnf("ikev2: refusing %s: %v", remote, err)
			s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
			return
		}
	}
	if err := verifyAuth(leaf.PublicKey, auth.Method, octets, auth.Data); err != nil {
		s.log.Warnf("ikev2: %s certificate AUTH failed: %v", remote, err)
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}

	// Our AUTH: sign ResponderSAInit | {Intermediate} | Ni | prf(SK_pr, IDr') with the server key.
	localIDBody := idPayloadBody(s.cfg.LocalID)
	respOctets := AuthOctets(sa.Suite.PRF, sa.ResponderSAInit, sa.Ni, sa.Keys.SKpr, localIDBody, sa.intAuth(sa.IKEAuthMsgID))
	method, authData, err := signAuth(s.serverCred, respOctets, sa.peerSigHashes)
	if err != nil {
		s.log.Printf("ikev2: signing server AUTH for %s: %v", remote, err)
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}

	b := payload.NewBuilder()
	b.Add(payload.TypeIDr, false, localIDBody)
	for _, der := range s.serverCred.chain {
		b.Add(payload.TypeCERT, false, payload.MarshalCert(payload.CertPayload{
			Encoding: payload.CertX509Signature, Data: der,
		}))
	}
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{Method: method, Data: authData}))
	s.log.Printf("ikev2: certificate auth ok for %s (id=%v)", remote, sa.PeerID.Type)
	s.finishIKEAuth(sa, hdr, inners, b, remote)
}

// handleEAPStart responds to the first (AUTH-less) IKE_AUTH: it sends IDr, our
// PSK AUTH, and the first EAP request (an MSCHAPv2 Challenge). The Child SA is
// deferred until EAP completes.
func (s *Server) handleEAPStart(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	// Our AUTH uses PSK (the server authenticates itself with the PSK even when
	// the client uses EAP).
	localIDBody := idPayloadBody(s.cfg.LocalID)
	ourAuth := computePSKAuth(sa.Suite.PRF, s.cfg.PSK, sa.ResponderSAInit, sa.Ni, sa.Keys.SKpr, localIDBody, sa.intAuth(sa.IKEAuthMsgID))

	// Start EAP-MSCHAPv2.
	srv := eap.NewServer(s.cfg.EAPCredentials, s.cfg.EAPServerName)
	sa.eapEAPID = 1
	challenge, err := srv.Begin(sa.eapEAPID)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	sa.eapServer = srv

	// Remember the Child SA request payloads for use once EAP completes.
	if p := findInner(inners, payload.TypeSA); p != nil {
		sa.eapSApay = append([]byte(nil), p.Body...)
	}
	if p := findInner(inners, payload.TypeTSi); p != nil {
		sa.eapTSipay = append([]byte(nil), p.Body...)
	}
	if p := findInner(inners, payload.TypeTSr); p != nil {
		sa.eapTSrpay = append([]byte(nil), p.Body...)
	}
	if p := findInner(inners, payload.TypeCP); p != nil {
		sa.eapCPpay = append([]byte(nil), p.Body...)
	}

	b := payload.NewBuilder()
	b.Add(payload.TypeIDr, false, localIDBody)
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: ourAuth,
	}))
	b.Add(payload.TypeEAP, false, challenge.Marshal())

	sa.RecvMsgID = hdr.MessageID + 1
	s.respondEncrypted(sa, payload.IKE_AUTH, hdr.MessageID, b.FirstType(), b.Bytes(), remote)
	s.log.Printf("ikev2: EAP-MSCHAPv2 started with %s", remote)
}

// handleEAPContinue processes a follow-up IKE_AUTH during EAP. Each such request
// carries either an EAP response or, once EAP has succeeded, the final AUTH
// payload computed from the MSK.
func (s *Server) handleEAPContinue(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	sa.RecvMsgID = hdr.MessageID + 1

	// If EAP already succeeded, this message must carry the final AUTH.
	if sa.eapMSK != nil {
		s.handleEAPFinalAuth(sa, hdr, inners, remote)
		return
	}

	eapPay := findInner(inners, payload.TypeEAP)
	if eapPay == nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	resp, err := eap.Parse(eapPay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}

	next, done, err := sa.eapServer.HandlePeer(resp)
	if err != nil {
		s.log.Warnf("ikev2: EAP with %s failed: %v", remote, err)
		// Send the EAP failure/next packet then an auth failure.
		b := payload.NewBuilder()
		b.Add(payload.TypeEAP, false, next.Marshal())
		s.respondEncrypted(sa, payload.IKE_AUTH, hdr.MessageID, b.FirstType(), b.Bytes(), remote)
		return
	}

	// Emit the next EAP packet (Challenge continuation, Success, or Failure).
	b := payload.NewBuilder()
	b.Add(payload.TypeEAP, false, next.Marshal())
	s.respondEncrypted(sa, payload.IKE_AUTH, hdr.MessageID, b.FirstType(), b.Bytes(), remote)

	if done {
		out := sa.eapServer.Outcome()
		if !out.Success {
			s.log.Warnf("ikev2: EAP authentication failed for %q from %s", out.Username, remote)
			return
		}
		// EAP succeeded: stash the MSK. The client will now send a final
		// IKE_AUTH containing its AUTH payload computed from the MSK.
		sa.eapMSK = out.MSK
		sa.EAPIdentity = out.Username
		s.log.Printf("ikev2: EAP-MSCHAPv2 success for %q from %s", out.Username, remote)
	}
}

// handleEAPFinalAuth verifies the initiator's MSK-based AUTH and completes the
// exchange by creating the Child SA.
func (s *Server) handleEAPFinalAuth(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	authPay := findInner(inners, payload.TypeAUTH)
	if authPay == nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}
	auth, err := payload.ParseAuth(authPay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}

	// The initiator signs InitiatorSAInit | {Intermediate} | Nr | prf(SK_pi, IDi'), keyed by the
	// EAP MSK instead of a PSK (RFC 7296 2.16).
	octets := AuthOctets(sa.Suite.PRF, sa.InitiatorSAInit, sa.Nr, sa.Keys.SKpi, sa.IDiForAuth, sa.intAuth(sa.IKEAuthMsgID))
	want := PSKAuth(sa.Suite.PRF, sa.eapMSK, octets)
	if !equalBytes(want, auth.Data) {
		s.log.Warnf("ikev2: EAP final AUTH from %s failed", remote)
		s.respondEncryptedNotify(sa, payload.IKE_AUTH, hdr.MessageID, payload.AuthenticationFailed, remote)
		return
	}

	// Our final AUTH, also keyed by the MSK.
	localIDBody := idPayloadBody(s.cfg.LocalID)
	respOctets := AuthOctets(sa.Suite.PRF, sa.ResponderSAInit, sa.Ni, sa.Keys.SKpr, localIDBody, sa.intAuth(sa.IKEAuthMsgID))
	ourAuth := PSKAuth(sa.Suite.PRF, sa.eapMSK, respOctets)

	b := payload.NewBuilder()
	b.Add(payload.TypeAUTH, false, payload.MarshalAuth(payload.AuthPayload{
		Method: payload.AuthSharedKeyMIC, Data: ourAuth,
	}))
	s.finishIKEAuth(sa, hdr, inners, b, remote)
}

// finishIKEAuth completes an IKE_AUTH exchange: it appends the optional CP
// reply and the Child SA to the response builder b (which already holds the
// identity/AUTH payloads as required by the auth mode), sends the encrypted
// response, and registers the Child SA.
func (s *Server) finishIKEAuth(sa *IKESA, hdr payload.Header, inners []payload.RawPayload,
	b *payload.Builder, remote *net.UDPAddr) {

	saPay := findInner(inners, payload.TypeSA)
	tsiPay := findInner(inners, payload.TypeTSi)
	tsrPay := findInner(inners, payload.TypeTSr)
	cpPay := findInner(inners, payload.TypeCP)

	// In the EAP flow the Child SA payloads arrived in the first IKE_AUTH, not
	// this final one; fall back to the saved copies.
	if saPay == nil && sa.eapSApay != nil {
		saPay = &payload.RawPayload{Type: payload.TypeSA, Body: sa.eapSApay}
	}
	if tsiPay == nil && sa.eapTSipay != nil {
		tsiPay = &payload.RawPayload{Type: payload.TypeTSi, Body: sa.eapTSipay}
	}
	if tsrPay == nil && sa.eapTSrpay != nil {
		tsrPay = &payload.RawPayload{Type: payload.TypeTSr, Body: sa.eapTSrpay}
	}
	if cpPay == nil && sa.eapCPpay != nil {
		cpPay = &payload.RawPayload{Type: payload.TypeCP, Body: sa.eapCPpay}
	}

	// MOBIKE: if the peer advertised support, confirm it. We always support it,
	// so the peer's advertisement alone enables address agility for this SA.
	if sa.peerMobike {
		sa.MobikeEnabled = true
		addMobikeSupported(b)
	}

	// CP address assignment.
	if cpPay != nil && s.cfg.AssignAddr != nil {
		if cpReply := s.buildCPReply(sa, cpPay); cpReply != nil {
			b.Add(payload.TypeCP, false, payload.MarshalCP(*cpReply))
		}
	}

	// Child SA negotiation.
	var respChild *ChildSA
	var acceptedESP payload.Proposal
	haveChild := saPay != nil && tsiPay != nil && tsrPay != nil
	if haveChild {
		if espSA, perr := payload.ParseSA(saPay.Body); perr == nil {
			if es, accepted, serr := SelectESPSuite(espSA); serr == nil {
				respChild, acceptedESP = s.setupChildSA(sa, es, accepted, tsiPay, tsrPay)
			}
		}
	}
	if respChild != nil {
		b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
			Proposals: []payload.Proposal{acceptedESP},
		}))
		// TSi is narrowed to the address config mode just handed out, not echoed
		// back as the initiator proposed it. See narrowTSiToAssignment.
		tsiBody := tsiPay.Body
		if narrowed, ok := narrowTSiToAssignment(respChild.TSi, sa); ok {
			respChild.TSi = narrowed
			tsiBody = payload.MarshalTS(narrowed)
		}
		b.Add(payload.TypeTSi, false, tsiBody)
		b.Add(payload.TypeTSr, false, tsrPay.Body)
		// USE_AGGFRAG (RFC 9347 section 3.1) is only agreed when BOTH peers send
		// it, so the echo is what turns it on. Echoing unconditionally would put
		// next-header 144 on the wire against a client that never asked for it.
		//
		// The echo carries the one-octet flags body, as the request must. An
		// empty notify is not a notify with default flags -- it is malformed,
		// and strongSwan refuses the whole message over it before looking at
		// anything else.
		if s.cfg.IPTFS {
			if flags, ok := s.acceptAggFrag(inners); ok {
				respChild.AggFrag = true
				respChild.AggFragFlags = flags
				respChild.IPTFSRate = s.cfg.IPTFSRate
				b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
					Protocol: payload.ProtoNone, Type: payload.UseAggFrag,
					Data: aggfrag.OurFlags.NotifyData(),
				}))
				s.log.Printf("ike: AGGFRAG (RFC 9347) negotiated; ESP next header %d, peer flags 0x%02x",
					aggfrag.ESPNextHeader, byte(flags))
			}
		}
	} else if haveChild {
		b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
			Protocol: payload.ProtoNone, Type: payload.TSUnacceptable,
		}))
	}

	sa.State = StateEstablished
	sa.RecvMsgID = hdr.MessageID + 1

	if respChild != nil {
		respChild.UDPEncap = s.udpEncap(sa, remote)
		respChild.ClientIP = sa.ClientIP
		respChild.ClientIP6 = sa.ClientIP6
		respChild.PeerAddr = remote
	}

	s.respondEncrypted(sa, payload.IKE_AUTH, hdr.MessageID, b.FirstType(), b.Bytes(), remote)
	s.log.Printf("ikev2: established IKE SA with %s (id=%v, client ip=%v)", remote, sa.PeerID.Type, sa.ClientIP)

	if respChild != nil {
		sa.Children[respChild.InboundSPI] = respChild
		s.log.Printf("ikev2: Child SA up (in=%#x out=%#x udpencap=%v)",
			respChild.InboundSPI, respChild.OutboundSPI, respChild.UDPEncap)
		if s.cfg.DataPath != nil {
			s.cfg.DataPath.AddChild(sa, respChild)
		}
		if s.cfg.OnChildSA != nil {
			s.cfg.OnChildSA(sa, respChild)
		}
	}
}

// narrowTSiToAssignment rewrites the initiator's proposed TSi to name exactly
// the address(es) config mode assigned it, and reports whether it changed
// anything.
//
// RFC 7296 section 2.19 gives the worked example, and it is the whole rule:
//
//	CP(CFG_REQUEST) = INTERNAL_ADDRESS()
//	TSi = (0, 0-65535, 0.0.0.0-255.255.255.255)   <- initiator, before it knows
//	...
//	CP(CFG_REPLY) = INTERNAL_ADDRESS(192.0.2.202)
//	TSi = (0, 0-65535, 192.0.2.202-192.0.2.202)   <- responder, narrowed
//
// An initiator asking for an address cannot put that address in the TSi of the
// same message, so what it sends is a placeholder: strongSwan sends 0.0.0.0/0,
// libreswan sends its own OUTER address. Echoing that back is not an answer.
// strongSwan accepts the echo -- 0.0.0.0/0 contains the lease, so its own
// narrowing still finds an overlap -- and veepin's client never inspected TSi
// at all, so both halves agreed and neither was right. libreswan installs the
// lease, re-narrows, finds 10.10.10.4/32 has no overlap with the 172.21.0.3/32
// it proposed, and answers TS_UNACCEPTABLE.
//
// The initiator's selector of each family is kept as the template so its
// protocol and port constraints survive; only the address range moves. A family
// the initiator did not offer a selector for gets none invented for it, and a
// family we assigned no address for is left exactly as proposed.
func narrowTSiToAssignment(tsi payload.TSPayload, sa *IKESA) (payload.TSPayload, bool) {
	if sa.ClientIP == nil && sa.ClientIP6 == nil {
		return tsi, false
	}
	var out []payload.TrafficSelector
	for _, want := range []struct {
		addr net.IP
		typ  payload.TSType
	}{
		{sa.ClientIP, payload.TSIPv4AddrRange},
		{sa.ClientIP6, payload.TSIPv6AddrRange},
	} {
		if want.addr == nil {
			continue
		}
		for _, sel := range tsi.Selectors {
			if sel.Type != want.typ {
				continue
			}
			sel.StartAddr = want.addr
			sel.EndAddr = want.addr
			out = append(out, sel)
			break
		}
	}
	if len(out) == 0 {
		return tsi, false
	}
	// Families we assigned nothing for keep whatever the initiator proposed;
	// dropping them would narrow a dual-stack request to half a tunnel.
	for _, sel := range tsi.Selectors {
		if (sel.Type == payload.TSIPv4AddrRange && sa.ClientIP != nil) ||
			(sel.Type == payload.TSIPv6AddrRange && sa.ClientIP6 != nil) {
			continue
		}
		out = append(out, sel)
	}
	return payload.TSPayload{Selectors: out}, true
}

// requestedFamilies reads a CFG_REQUEST for the address families it names.
//
// A request naming neither is treated as asking for IPv4. RFC 7296 section
// 3.15.2 obliges a responder to "recognize a field of type INTERNAL_IP4_ADDRESS
// or INTERNAL_IP6_ADDRESS" and return an address "of the requested type", and
// says nothing about a request that names no type at all -- but a peer that
// sends a CP payload is asking to be given an address, and every peer this has
// been run against that asks for one asks for IPv4.
func requestedFamilies(req payload.CPPayload) AddressRequest {
	var want AddressRequest
	for _, attr := range req.Attrs {
		switch attr.Type {
		case payload.CFGInternalIP4Address:
			want.IP4 = true
		case payload.CFGInternalIP6Address:
			want.IP6 = true
		}
	}
	if !want.IP4 && !want.IP6 {
		want.IP4 = true
	}
	return want
}

// buildCPReply allocates an internal address and builds a CFG_REPLY.
func (s *Server) buildCPReply(sa *IKESA, cpPay *payload.RawPayload) *payload.CPPayload {
	req, err := payload.ParseCP(cpPay.Body)
	if err != nil || req.Type != payload.CFGRequest {
		return nil
	}
	a, err := s.cfg.AssignAddr(requestedFamilies(req))
	if err != nil || (a.IP4 == nil && a.IP6 == nil) {
		s.log.Warnf("ikev2: address assignment failed: %v", err)
		return nil
	}
	sa.ClientIP = a.IP4
	sa.ClientIP6 = a.IP6
	sa.assigned = a
	reply := &payload.CPPayload{Type: payload.CFGReply}
	if a.IP4 != nil {
		reply.Attrs = append(reply.Attrs, payload.CFGAttr{Type: payload.CFGInternalIP4Address, Value: a.IP4.To4()})
		if a.Netmask != nil {
			reply.Attrs = append(reply.Attrs, payload.CFGAttr{Type: payload.CFGInternalIP4Netmask, Value: a.Netmask.To4()})
		}
	}
	if a.IP6 != nil {
		// INTERNAL_IP6_ADDRESS is 16 address octets followed by a 1-octet prefix
		// length (RFC 7296 3.15.1), unlike the IPv4 address/netmask split.
		val := append(append([]byte(nil), a.IP6.To16()...), byte(a.Prefix6))
		reply.Attrs = append(reply.Attrs, payload.CFGAttr{Type: payload.CFGInternalIP6Address, Value: val})
	}
	for _, d := range a.DNS {
		if v4 := d.To4(); v4 != nil {
			reply.Attrs = append(reply.Attrs, payload.CFGAttr{Type: payload.CFGInternalIP4DNS, Value: v4})
		} else if v6 := d.To16(); v6 != nil {
			reply.Attrs = append(reply.Attrs, payload.CFGAttr{Type: payload.CFGInternalIP6DNS, Value: v6})
		}
	}
	return reply
}

// setupChildSA derives the Child SA keys and returns the ChildSA plus the
// accepted ESP proposal (with our inbound SPI substituted).
func (s *Server) setupChildSA(sa *IKESA, es ESPSuite, accepted payload.Proposal,
	tsiPay, tsrPay *payload.RawPayload) (*ChildSA, payload.Proposal) {

	var outboundSPI uint32
	if len(accepted.SPI) == 4 {
		outboundSPI = beU32(accepted.SPI)
	}
	inboundSPI := newChildSPI()
	accepted.SPI = u32BE(inboundSPI)

	tsi, _ := payload.ParseTS(tsiPay.Body)
	tsr, _ := payload.ParseTS(tsrPay.Body)

	encLen := es.Cipher.KeyLen()
	integLen := 0
	if es.Integ != nil {
		integLen = es.Integ.KeyLen
	}
	total := 2*encLen + 2*integLen
	km := DeriveChildKeys(sa.Suite.PRF, sa.Keys.SKd, nil, sa.Ni, sa.Nr, total)

	off := 0
	take := func(n int) []byte { b := km[off : off+n]; off += n; return b }
	encI := take(encLen)
	var integI []byte
	if integLen > 0 {
		integI = take(integLen)
	}
	encR := take(encLen)
	var integR []byte
	if integLen > 0 {
		integR = take(integLen)
	}

	child := &ChildSA{
		InboundSPI:  inboundSPI,
		OutboundSPI: outboundSPI,
		Suite:       es,
		EncrOut:     encR, IntegOut: integR,
		EncrIn: encI, IntegIn: integI,
		TSi: tsi, TSr: tsr,
	}
	return child, accepted
}

func findInner(inners []payload.RawPayload, t payload.PayloadType) *payload.RawPayload {
	for i := range inners {
		if inners[i].Type == t {
			return &inners[i]
		}
	}
	return nil
}

// findAllInner returns every payload of type t, in order (CERT payloads, of
// which a chain carries several).
func findAllInner(inners []payload.RawPayload, t payload.PayloadType) []payload.RawPayload {
	var out []payload.RawPayload
	for i := range inners {
		if inners[i].Type == t {
			out = append(out, inners[i])
		}
	}
	return out
}

// parseCertChain splits a run of CERT payloads into the leaf's DER (the first,
// the end-entity certificate) and the remaining intermediates. Only X.509
// signature certificates are accepted.
func parseCertChain(certs []payload.RawPayload) (leafDER []byte, intermediates [][]byte, err error) {
	for i, cp := range certs {
		c, perr := payload.ParseCert(cp.Body)
		if perr != nil {
			return nil, nil, perr
		}
		if c.Encoding != payload.CertX509Signature {
			return nil, nil, fmt.Errorf("ike: unsupported certificate encoding %d", c.Encoding)
		}
		if i == 0 {
			leafDER = c.Data
		} else {
			intermediates = append(intermediates, c.Data)
		}
	}
	if len(leafDER) == 0 {
		return nil, nil, fmt.Errorf("ike: empty certificate payload")
	}
	return leafDER, intermediates, nil
}

func beU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func u32BE(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// u64BE / beU64 convert an 8-octet IKE SPI to and from its big-endian wire form.
func u64BE(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}
func beU64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }

// acceptAggFrag decides whether to echo the initiator's USE_AGGFRAG, and
// reports the flags it required of us.
//
// Declining is done by staying silent, not by erroring: RFC 9347 section 5.1
// says a responder that cannot meet a requirement flag simply does not respond
// with the notification, and the Child SA is then established carrying plain
// inner IP. Failing the exchange instead would turn an option the initiator
// offered into a refused connection.
func (s *Server) acceptAggFrag(inners []payload.RawPayload) (aggfrag.Flags, bool) {
	n := findNotify(inners, payload.UseAggFrag)
	if n == nil {
		return 0, false
	}
	flags, err := aggfrag.ParseFlags(n.Data)
	if err != nil {
		s.log.Printf("ike: %v; not enabling AGGFRAG", err)
		return 0, false
	}
	if flags.Unsupported() {
		s.log.Printf("ike: peer requires AGGFRAG flags 0x%02x this does not implement; "+
			"not enabling AGGFRAG", byte(flags))
		return 0, false
	}
	return flags, true
}
