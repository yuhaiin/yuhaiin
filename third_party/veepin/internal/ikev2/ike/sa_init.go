package ike

import (
	"net"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// handleIKESAInit processes an IKE_SA_INIT request and sends the response.
//
//	Initiator                     Responder
//	HDR, SAi1, KEi, Ni,
//	  N(NAT_DETECTION_*)  -->
//	                      <--  HDR, SAr1, KEr, Nr, N(NAT_DETECTION_*)
func (s *Server) handleIKESAInit(pkt []byte, hdr payload.Header, remote *net.UDPAddr, on4500 bool) {
	if hdr.IsResponse() {
		return
	}
	msg, err := payload.ParseMessage(pkt)
	if err != nil {
		s.log.Printf("ikev2: SA_INIT parse from %s: %v", remote, err)
		return
	}

	saPay := msg.Find(payload.TypeSA)
	kePay := msg.Find(payload.TypeKE)
	noncePay := msg.Find(payload.TypeNonce)
	if saPay == nil || kePay == nil || noncePay == nil {
		s.sendUnauthNotify(hdr, remote, on4500, payload.InvalidSyntax)
		return
	}

	// Anti-DoS, before any asymmetric work.
	//
	// Everything below this point -- selecting a suite, the Diffie-Hellman
	// computation, deriving key material, and the SA state held afterwards --
	// is performed for a peer that has proved nothing, at an address that is
	// trivially spoofable over UDP.
	//
	// Under pressure the responder demands a cookie first (RFC 7296 2.6).
	// That costs it nothing: the cookie is derived, not stored, and an attacker
	// forging a source address never receives the reply and so can never return
	// it. A real initiator retries with the cookie and proceeds. The admission
	// gate is the floor beneath that, covering the case where an attacker can
	// see the replies.
	if !s.checkCookie(msg, hdr, noncePay.Body, remote, on4500) {
		return
	}
	if r := s.gate.Admit(remote); r != dataplane.Admitted {
		s.log.Warnf("ikev2: refusing SA_INIT from %s: %v", remote, r)
		return
	}
	defer s.gate.Done()

	sa, err := payload.ParseSA(saPay.Body)
	if err != nil {
		s.sendUnauthNotify(hdr, remote, on4500, payload.InvalidSyntax)
		return
	}
	suite, accepted, err := SelectIKESuite(sa)
	if err != nil {
		s.sendUnauthNotify(hdr, remote, on4500, payload.NoProposalChosen)
		return
	}

	ke, err := payload.ParseKE(kePay.Body)
	if err != nil {
		s.sendUnauthNotify(hdr, remote, on4500, payload.InvalidSyntax)
		return
	}
	if ke.Group != suite.DHID {
		data := []byte{byte(suite.DHID >> 8), byte(suite.DHID)}
		s.sendUnauthNotifyData(hdr, remote, on4500, payload.InvalidKEPayload, data)
		return
	}

	dh, err := transform.DH(suite.DHID)
	if err != nil {
		s.sendUnauthNotify(hdr, remote, on4500, payload.NoProposalChosen)
		return
	}
	ourPub, err := dh.Generate()
	if err != nil {
		s.log.Printf("ikev2: DH generate: %v", err)
		return
	}
	shared, err := dh.ComputeSecret(ke.KeyData)
	if err != nil {
		s.log.Printf("ikev2: DH compute from %s: %v", remote, err)
		s.sendUnauthNotify(hdr, remote, on4500, payload.InvalidSyntax)
		return
	}

	newSA := newIKESA()
	newSA.InitiatorSPI = hdr.InitiatorSPI
	newSA.ResponderSPI = newIKESPI()
	newSA.WeAreInitiator = false
	newSA.Suite = suite
	newSA.RemoteAddr = remote
	newSA.OnPort4500 = on4500
	newSA.Ni = payload.ParseNonce(noncePay.Body)
	newSA.Nr = randomNonce(suite.PRF.PreferredKeyLen)
	newSA.SharedKey = shared
	newSA.InitiatorSAInit = append([]byte(nil), pkt...)

	// NAT detection (RFC 7296 2.23). Compare the peer-supplied hashes against
	// what we actually observe for source (the peer) and destination (us).
	newSA.NAT = s.detectNAT(msg.FindAll(payload.TypeNotify), hdr.InitiatorSPI, hdr.ResponderSPI, remote, on4500)

	// IKE fragmentation (RFC 7383) is negotiated here: if the initiator supports
	// it we echo the notify and enable reassembly of the peer's later protected
	// messages. We never fragment our own output.
	newSA.fragEnabled = findFragSupported(msg.Payloads)

	// RFC 7427 signature hashes the initiator will accept, for a certificate
	// AUTH the server may sign in IKE_AUTH.
	newSA.peerSigHashes = findSigHashes(msg.Payloads)

	// Additional key exchange (RFC 9370). Accept ML-KEM-768 only when the
	// initiator both proposed it in an ADDKE1 transform and advertised
	// INTERMEDIATE_EXCHANGE_SUPPORTED, since the exchange that carries it is
	// the one thing it cannot be done without.
	if hasIntermediateSupport(msg) {
		for _, p := range sa.Proposals {
			if p.Num != accepted.Num {
				continue
			}
			if group, ok := SelectADDKE(p); ok {
				newSA.ADDKEGroup = group
				accepted.Transforms = append(accepted.Transforms,
					payload.Transform{Type: payload.TransformADDKE1, ID: group})
				// Logged so an interop cell can assert the post-quantum path
				// actually came up: a bare ping passes just as happily on a
				// silent fallback to the classical group alone.
				s.log.Printf("ikev2: %s negotiated additional key exchange ML-KEM-768", remote)
			}
			break
		}
	}

	// Under RequirePostQuantum a classical-only initiator is refused here rather
	// than served. Distinguishing the two ways it can fail is worth the extra
	// branch: a peer that proposed ML-KEM without the intermediate exchange is
	// misconfigured differently from one that proposed no ML-KEM at all, and an
	// operator reading the log should not have to guess which.
	if s.cfg.RequirePostQuantum && newSA.ADDKEGroup == 0 {
		switch {
		case !hasIntermediateSupport(msg):
			s.log.Warnf("ikev2: refusing %s: post-quantum is required and the initiator "+
				"did not advertise INTERMEDIATE_EXCHANGE_SUPPORTED (RFC 9242), which the "+
				"ML-KEM exchange cannot be carried without", remote)
		default:
			s.log.Warnf("ikev2: refusing %s: post-quantum is required and the initiator "+
				"proposed no ADDKE1 key exchange this server supports (RFC 9370, ML-KEM-768)", remote)
		}
		s.sendUnauthNotify(hdr, remote, on4500, payload.NoProposalChosen)
		return
	}

	_, keys := DeriveIKEKeys(
		suite.PRF, shared, newSA.Ni, newSA.Nr,
		newSA.InitiatorSPI, newSA.ResponderSPI,
		suite.encKeyLen(), suite.integKeyLen(),
	)
	newSA.Keys = keys
	newSA.State = StateSAInitDone

	// Build response: SAr1, KEr, Nr, NAT_DETECTION_SOURCE_IP, NAT_DETECTION_DESTINATION_IP.
	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: []payload.Proposal{accepted},
	}))
	b.Add(payload.TypeKE, false, payload.MarshalKE(payload.KEPayload{
		Group: suite.DHID, KeyData: ourPub,
	}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(newSA.Nr))
	s.addNATDetection(b, newSA.InitiatorSPI, newSA.ResponderSPI, remote, on4500)
	if newSA.fragEnabled {
		addFragSupported(b)
	}
	// Echo INTERMEDIATE_EXCHANGE_SUPPORTED only when an additional key exchange
	// was actually negotiated, so an initiator never sees an invitation to send
	// an exchange this SA has nothing to put in.
	if newSA.ADDKEGroup != 0 {
		addIntermediateNotify(b)
	}
	// When the server can do certificate auth, advertise the RFC 7427 signature
	// hashes and ask for a certificate (an empty CERTREQ = "any CA I trust"), so
	// a certificate-capable initiator sends its chain and signs a Digital
	// Signature. Harmless to a PSK/EAP client, which ignores both.
	if s.serverCred != nil || s.cfg.ClientCAs != nil {
		addSigHashNotify(b)
		b.Add(payload.TypeCERTREQ, false, payload.MarshalCertReq(payload.CertReqPayload{
			Encoding: payload.CertX509Signature,
		}))
	}

	chain := b.Bytes()
	respHdr := payload.Header{
		InitiatorSPI: newSA.InitiatorSPI,
		ResponderSPI: newSA.ResponderSPI,
		NextPayload:  b.FirstType(),
		Version:      0x20,
		ExchangeType: payload.IKE_SA_INIT,
		Flags:        payload.FlagResponse,
		MessageID:    0,
		Length:       uint32(payload.HeaderLen + len(chain)),
	}
	resp := append(respHdr.Marshal(nil), chain...)
	newSA.ResponderSAInit = append([]byte(nil), resp...)
	newSA.RecvMsgID = 1

	// Read any SA fields for logging before publishing the SA: once storeSA
	// makes it reachable, another exchange (e.g. a MOBIKE UPDATE_SA_ADDRESSES
	// that rewrites NAT) may mutate it under sa.mu, which this goroutine does
	// not hold here.
	natDetected := newSA.NAT.natDetected()
	rspi := newSA.ResponderSPI

	s.storeSA(newSA)
	s.send(resp, remote, on4500)
	s.log.Printf("ikev2: SA_INIT done with %s (rSPI=%#x, encr=%d prf=%d dh=%d, nat=%v)",
		remote, rspi, suite.EncrID, suite.PRFID, suite.DHID, natDetected)
}

// detectNAT compares the peer's NAT_DETECTION_* hashes against observed values.
// The initiator computes the destination hash over the server IP/port it is
// sending to, so we use our public IP and the port this datagram arrived on.
// It scans the notify payloads of any message carrying NAT detection: the
// IKE_SA_INIT (using its zero responder SPI) or a MOBIKE UPDATE_SA_ADDRESSES on
// an established SA (using both SPIs).
func (s *Server) detectNAT(payloads []payload.RawPayload, spiI, spiR uint64, remote *net.UDPAddr, on4500 bool) natInfo {
	var info natInfo
	var srcSeen, dstSeen bool

	ourPort := uint16(s.cfg.Port500)
	if on4500 {
		ourPort = uint16(s.cfg.Port4500)
	}
	ourIP := s.cfg.PublicIP
	if ourIP == nil {
		ourIP = net.IPv4zero
	}

	for _, p := range payloads {
		if p.Type != payload.TypeNotify {
			continue
		}
		n, err := payload.ParseNotify(p.Body)
		if err != nil {
			continue
		}
		switch n.Type {
		case payload.NATDetectionSourceIP:
			srcSeen = true
			// Source = the initiator, as we observe it on the wire.
			want := natDetectionHash(spiI, spiR, remote.IP, uint16(remote.Port))
			if !equalBytes(want, n.Data) {
				info.peerBehindNAT = true
			}
		case payload.NATDetectionDestinationIP:
			dstSeen = true
			// Destination = us, as the initiator addressed us.
			want := natDetectionHash(spiI, spiR, ourIP, ourPort)
			if !equalBytes(want, n.Data) {
				// Only trust this if we actually know our public IP.
				if s.cfg.PublicIP != nil {
					info.weAreBehindNAT = true
				}
			}
		}
	}
	if !srcSeen && !dstSeen {
		return natInfo{}
	}
	return info
}

// addNATDetection appends our own NAT_DETECTION_SOURCE_IP (this responder) and
// NAT_DETECTION_DESTINATION_IP (the initiator) notifies so the peer can detect
// NAT on its side too.
func (s *Server) addNATDetection(b *payload.Builder, spiI, spiR uint64, remote *net.UDPAddr, on4500 bool) {
	ourIP := s.cfg.PublicIP
	if ourIP == nil {
		ourIP = net.IPv4zero
	}
	ourPort := uint16(s.cfg.Port500)
	if on4500 {
		ourPort = uint16(s.cfg.Port4500)
	}
	// Source = us.
	srcHash := natDetectionHash(spiI, spiR, ourIP, ourPort)
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionSourceIP, Data: srcHash,
	}))
	// Destination = the initiator as we see it.
	dstHash := natDetectionHash(spiI, spiR, remote.IP, uint16(remote.Port))
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: payload.NATDetectionDestinationIP, Data: dstHash,
	}))
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sendUnauthNotify sends an unencrypted Notify response (IKE_SA_INIT errors).
// checkCookie applies RFC 7296 2.6. It reports whether the exchange may proceed.
//
// A cookie is only demanded when the responder is under enough half-open
// pressure to justify it. Demanding one unconditionally would add a round trip
// to every handshake for no benefit when nothing is attacking; demanding one
// never would leave the responder doing asymmetric work for spoofed traffic.
func (s *Server) checkCookie(msg *payload.Message, hdr payload.Header, nonce []byte, remote *net.UDPAddr, on4500 bool) bool {
	if s.gate.HalfOpen() < cookieThreshold {
		return true
	}

	// The initiator echoes the cookie as the first notify of its retry.
	for _, p := range msg.Payloads {
		if p.Type != payload.TypeNotify {
			continue
		}
		n, err := payload.ParseNotify(p.Body)
		if err != nil || n.Type != payload.Cookie {
			continue
		}
		if s.cookies.valid(n.Data, hdr.InitiatorSPI, nonce, remote) {
			return true
		}
		// A wrong cookie is answered with a fresh one rather than dropped: it
		// is most likely one issued under a secret that has since rotated
		// twice, and a legitimate initiator should be able to recover.
		break
	}

	cookie := s.cookies.issue(hdr.InitiatorSPI, nonce, remote)
	if len(cookie) == 0 {
		// The jar could not produce one. Falling through to the gate is better
		// than refusing every handshake.
		return true
	}
	s.sendUnauthNotifyData(hdr, remote, on4500, payload.Cookie, cookie)
	return false
}

func (s *Server) sendUnauthNotify(reqHdr payload.Header, remote *net.UDPAddr, on4500 bool, nt payload.NotifyType) {
	s.sendUnauthNotifyData(reqHdr, remote, on4500, nt, nil)
}

func (s *Server) sendUnauthNotifyData(reqHdr payload.Header, remote *net.UDPAddr, on4500 bool, nt payload.NotifyType, data []byte) {
	b := payload.NewBuilder()
	b.Add(payload.TypeNotify, false, payload.MarshalNotify(payload.NotifyPayload{
		Protocol: payload.ProtoNone, Type: nt, Data: data,
	}))
	chain := b.Bytes()
	h := payload.Header{
		InitiatorSPI: reqHdr.InitiatorSPI,
		ResponderSPI: reqHdr.ResponderSPI,
		NextPayload:  b.FirstType(),
		Version:      0x20,
		ExchangeType: reqHdr.ExchangeType,
		Flags:        payload.FlagResponse,
		MessageID:    reqHdr.MessageID,
		Length:       uint32(payload.HeaderLen + len(chain)),
	}
	s.send(append(h.Marshal(nil), chain...), remote, on4500)
}
