package ike

import (
	"net"

	"github.com/xen0bit/veepin/internal/ikev2/payload"
	"github.com/xen0bit/veepin/internal/ikev2/transform"
)

// handleRekeyIKE processes a CREATE_CHILD_SA that rekeys the IKE SA itself
// (RFC 7296 2.18). It runs a fresh DH exchange, derives the new SA's control
// keys from the old SA's SK_d, migrates every Child SA to the new IKE SA
// unchanged (their ESP keys are not touched, so the data path never pauses),
// and registers the replacement. The response is protected under the *old* SA;
// the peer then deletes the old SA with an INFORMATIONAL. reqSA is the
// already-parsed request SA payload (first proposal is Protocol=IKE).
//
// Called with sa.mu held (from handleSecured).
func (s *Server) handleRekeyIKE(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr, reqSA payload.SAPayload) {
	noncePay := findInner(inners, payload.TypeNonce)
	kePay := findInner(inners, payload.TypeKE)
	if noncePay == nil || kePay == nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}
	if len(reqSA.Proposals[0].SPI) != 8 {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}
	suite, accepted, err := SelectIKESuite(reqSA)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.NoProposalChosen, remote)
		return
	}
	ke, err := payload.ParseKE(kePay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}
	if ke.Group != suite.DHID {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.InvalidKEPayload, remote)
		return
	}

	dh, err := transform.DH(suite.DHID)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.NoProposalChosen, remote)
		return
	}
	ourPub, err := dh.Generate()
	if err != nil {
		s.log.Printf("ikev2: rekey-IKE DH generate: %v", err)
		return
	}
	shared, err := dh.ComputeSecret(ke.KeyData)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}

	newSPIi := beU64(reqSA.Proposals[0].SPI)
	newSPIr := newIKESPI()
	ni := payload.ParseNonce(noncePay.Body)
	nr := randomNonce(suite.PRF.PreferredKeyLen)

	newKeys := DeriveRekeyedIKEKeys(suite.PRF, sa.Keys.SKd, shared, ni, nr,
		newSPIi, newSPIr, suite.encKeyLen(), suite.integKeyLen())

	// Build the replacement IKE SA. It inherits the peer's transport state, the
	// negotiated options, and — crucially — the Child SAs, moved across so the
	// ESP data path is untouched. Message IDs reset: this CREATE_CHILD_SA is the
	// last exchange on the old SA, the new SA starts at zero.
	newSA := newIKESA()
	newSA.InitiatorSPI = newSPIi
	newSA.ResponderSPI = newSPIr
	newSA.WeAreInitiator = false
	newSA.Suite = suite
	newSA.Keys = newKeys
	newSA.State = StateEstablished
	newSA.RemoteAddr = remote
	newSA.OnPort4500 = sa.OnPort4500
	newSA.NAT = sa.NAT
	newSA.MobikeEnabled = sa.MobikeEnabled
	newSA.fragEnabled = sa.fragEnabled
	newSA.ClientIP = sa.ClientIP
	newSA.ClientIP6 = sa.ClientIP6
	newSA.assigned = sa.assigned
	newSA.PeerID = sa.PeerID
	newSA.RecvMsgID = 0
	newSA.SendMsgID = 0
	newSA.Children = sa.Children

	// Detach the migrated state from the old SA so its imminent deletion (the
	// peer sends INFORMATIONAL{D(IKE)} next) neither tears down the inherited
	// Child SA data paths nor releases the assigned address.
	sa.Children = make(map[uint32]*ChildSA)
	sa.ClientIP = nil
	sa.State = StateDeleting

	// Response under the OLD SA: SA (accepted proposal carrying our new
	// responder SPI), Nr, KEr.
	accepted.SPI = u64BE(newSPIr)
	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{Proposals: []payload.Proposal{accepted}}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(nr))
	b.Add(payload.TypeKE, false, payload.MarshalKE(payload.KEPayload{Group: suite.DHID, KeyData: ourPub}))
	s.respondEncrypted(sa, payload.CREATE_CHILD_SA, hdr.MessageID, b.FirstType(), b.Bytes(), remote)

	s.storeSA(newSA)
	s.log.Printf("ikev2: IKE SA rekeyed with %s (old rSPI=%#x new rSPI=%#x, %d child(ren) migrated)",
		remote, sa.ResponderSPI, newSPIr, len(newSA.Children))
}

// handleCreateChildSA processes a CREATE_CHILD_SA request. An ESP proposal
// creates or rekeys a Child SA (a REKEY_SA notify names the SA being replaced,
// but the negotiation is the same as a fresh child); an IKE proposal rekeys the
// IKE SA itself and is dispatched to handleRekeyIKE.
//
//	HDR, SK{[N(REKEY_SA)], SA, Ni, [KEi], TSi, TSr} -->   (Child SA)
//	                    <-- HDR, SK{SA, Nr, [KEr], TSi, TSr}
//	HDR, SK{SA(IKE), Ni, KEi}                       -->   (IKE SA rekey)
//	                    <-- HDR, SK{SA(IKE), Nr, KEr}
func (s *Server) handleCreateChildSA(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	saPay := findInner(inners, payload.TypeSA)

	// Advance the responder message-ID window regardless of outcome.
	sa.RecvMsgID = hdr.MessageID + 1

	if saPay == nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}
	reqSA, err := payload.ParseSA(saPay.Body)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}

	// An IKE proposal means the peer is rekeying the IKE SA itself (RFC 7296
	// 2.18): a fresh DH exchange, the Child SAs inherited unchanged. An ESP
	// proposal is a Child SA create/rekey and falls through below.
	if len(reqSA.Proposals) > 0 && reqSA.Proposals[0].Protocol == payload.ProtoIKE {
		s.handleRekeyIKE(sa, hdr, inners, remote, reqSA)
		return
	}

	noncePay := findInner(inners, payload.TypeNonce)
	tsiPay := findInner(inners, payload.TypeTSi)
	tsrPay := findInner(inners, payload.TypeTSr)
	if noncePay == nil || tsiPay == nil || tsrPay == nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.InvalidSyntax, remote)
		return
	}
	espSA := reqSA
	es, accepted, err := SelectESPSuite(espSA)
	if err != nil {
		s.respondEncryptedNotify(sa, payload.CREATE_CHILD_SA, hdr.MessageID, payload.NoProposalChosen, remote)
		return
	}

	// Fresh nonces for the child key derivation. Note: per RFC 7296 the child
	// KEYMAT uses Ni|Nr from *this* exchange. We reuse the sa.Ni/sa.Nr fields
	// transiently by deriving with the CREATE_CHILD_SA nonces.
	initNonce := payload.ParseNonce(noncePay.Body)
	respNonce := randomNonce(sa.Suite.PRF.PreferredKeyLen)

	// Swap in these nonces for derivation without disturbing the IKE SA nonces.
	savedNi, savedNr := sa.Ni, sa.Nr
	sa.Ni, sa.Nr = initNonce, respNonce
	child, acceptedESP := s.setupChildSA(sa, es, accepted, tsiPay, tsrPay)
	sa.Ni, sa.Nr = savedNi, savedNr

	// Response chain: SA, Nr, TSi, TSr.
	b := payload.NewBuilder()
	b.Add(payload.TypeSA, false, payload.MarshalSA(payload.SAPayload{
		Proposals: []payload.Proposal{acceptedESP},
	}))
	b.Add(payload.TypeNonce, false, payload.MarshalNonce(respNonce))
	b.Add(payload.TypeTSi, false, tsiPay.Body)
	b.Add(payload.TypeTSr, false, tsrPay.Body)

	child.UDPEncap = s.udpEncap(sa, remote)
	child.ClientIP = sa.ClientIP
	child.ClientIP6 = sa.ClientIP6
	child.PeerAddr = remote

	s.respondEncrypted(sa, payload.CREATE_CHILD_SA, hdr.MessageID, b.FirstType(), b.Bytes(), remote)

	sa.Children[child.InboundSPI] = child
	s.log.Printf("ikev2: CREATE_CHILD_SA up with %s (in=%#x out=%#x)", remote, child.InboundSPI, child.OutboundSPI)
	if s.cfg.DataPath != nil {
		s.cfg.DataPath.AddChild(sa, child)
	}
	if s.cfg.OnChildSA != nil {
		s.cfg.OnChildSA(sa, child)
	}
}

// handleInformational processes an INFORMATIONAL request: DELETE payloads,
// liveness checks (empty request), and status notifies.
//
//	HDR, SK{[N,] [D,] [CP,]} -->
//	                    <-- HDR, SK{[N,] [D,]}
func (s *Server) handleInformational(sa *IKESA, hdr payload.Header, inners []payload.RawPayload, remote *net.UDPAddr) {
	sa.RecvMsgID = hdr.MessageID + 1

	// Liveness probe: an empty INFORMATIONAL request must get an empty
	// (but encrypted) response.
	if len(inners) == 0 {
		s.respondEncrypted(sa, payload.INFORMATIONAL, hdr.MessageID, payload.NoNextPayload, nil, remote)
		return
	}

	b := payload.NewBuilder()

	// MOBIKE (RFC 4555): UPDATE_SA_ADDRESSES relocates the SA, COOKIE2 is a
	// return-routability probe. Both append their response notifies to b.
	s.handleMobikeInformational(sa, inners, remote, b)

	deleteIKE := false
	var deletedChildSPIs [][]byte

	for _, p := range inners {
		if p.Type != payload.TypeDelete {
			continue
		}
		d, err := payload.ParseDelete(p.Body)
		if err != nil {
			continue
		}
		switch d.Protocol {
		case payload.ProtoIKE:
			// Peer is tearing down the whole IKE SA.
			deleteIKE = true
		case payload.ProtoESP:
			// Delete the named Child SAs; respond with our matching SPIs.
			for _, spi := range d.SPIs {
				if len(spi) != 4 {
					continue
				}
				out := beU32(spi)
				for in, c := range sa.Children {
					if c.OutboundSPI == out {
						deletedChildSPIs = append(deletedChildSPIs, u32BE(c.InboundSPI))
						if s.cfg.DataPath != nil {
							s.cfg.DataPath.RemoveChild(sa, c)
						}
						delete(sa.Children, in)
						s.log.Printf("ikev2: deleted Child SA (out=%#x) at peer request", out)
					}
				}
			}
		}
	}

	if len(deletedChildSPIs) > 0 {
		b.Add(payload.TypeDelete, false, payload.MarshalDelete(payload.DeletePayload{
			Protocol: payload.ProtoESP, SPISize: 4, SPIs: deletedChildSPIs,
		}))
	}

	// Send response (empty if we only processed an IKE delete).
	s.respondEncrypted(sa, payload.INFORMATIONAL, hdr.MessageID, b.FirstType(), b.Bytes(), remote)

	if deleteIKE {
		sa.State = StateClosed
		if s.cfg.DataPath != nil {
			for _, c := range sa.Children {
				s.cfg.DataPath.RemoveChild(sa, c)
			}
		}
		s.deleteSA(sa)
		s.log.Printf("ikev2: IKE SA with %s deleted at peer request", remote)
	}
}
