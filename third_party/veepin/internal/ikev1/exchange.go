package ikev1

import (
	"fmt"
)

// integKeyLen returns the HMAC key length in octets for an ESP integrity
// transform.
func integKeyLen(integID uint16) int {
	if integID == espAuthHMACSHA256128 {
		return 32
	}
	return 20 // HMAC-SHA1
}

// --- initiator ---

func (s *Session) sendMM1() error {
	s.saBodyI = buildPhase1SA(defaultIKEProposals(s.authMethod()))
	// The SA payload is what HASH_I/HASH_R authenticate; the Vendor IDs that
	// follow it announce NAT-T support and are outside that hash.
	payloads := append([]payload{{typ: payloadSA, body: s.saBodyI}}, natTVendorPayloads()...)
	msg := marshalMessage(s.mmHeader(exchangeMain, 0, 0), payloads)
	return s.transmit(msg)
}

func (s *Session) dispatchInitiator(h header, first uint8, rest []byte) error {
	switch s.state {
	case stWaitMM2:
		return s.initHandleMM2(h, first, rest)
	case stWaitMM4:
		return s.initHandleMM4(first, rest)
	case stWaitMM6:
		return s.initHandleMM6(first, rest)
	case stWaitAM2:
		return s.initHandleAM2(h, first, rest)
	case stWaitXAuthReq, stWaitXAuthSet, stWaitCfgRep:
		return s.handleTransaction(h, first, rest)
	case stWaitQM2:
		return s.initHandleQM2(first, rest)
	}
	return nil
}

func (s *Session) initHandleMM2(h header, first uint8, rest []byte) error {
	s.respCookie = h.respCookie
	payloads, _, err := parsePayloads(first, rest)
	if err != nil {
		return err
	}
	sa, ok := findPayload(payloads, payloadSA)
	if !ok {
		return fmt.Errorf("ikev1: MM2 without SA")
	}
	_, _, transforms, err := parseSA(sa.body)
	if err != nil {
		return err
	}
	if len(transforms) != 1 {
		return fmt.Errorf("ikev1: MM2 must choose exactly one transform")
	}
	prop, ok := ikePropFromAttrs(transforms[0].attrs)
	if !ok || !s.supportedIKE(prop) {
		return fmt.Errorf("ikev1: responder chose an unsupported IKE proposal")
	}
	s.prop = prop
	s.peerNATT = peerSupportsNATT(payloads)
	if !s.peerNATT {
		return errNoNATT
	}
	s.advance()

	dh, err := dhGroup(prop.group)
	if err != nil {
		return err
	}
	s.dh = dh
	s.localPub, err = dh.Generate()
	if err != nil {
		return err
	}
	s.ni = nonce()
	mm3 := []payload{
		{typ: payloadKE, body: s.localPub},
		{typ: payloadNonce, body: s.ni},
	}
	if s.peerNATT {
		mm3 = append(mm3, s.natdPayloads()...)
	}
	msg := marshalMessage(s.mmHeader(exchangeMain, 0, 0), mm3)
	s.state = stWaitMM4
	return s.transmit(msg)
}

func (s *Session) initHandleMM4(first uint8, rest []byte) error {
	payloads, _, err := parsePayloads(first, rest)
	if err != nil {
		return err
	}
	ke, ok1 := findPayload(payloads, payloadKE)
	nc, ok2 := findPayload(payloads, payloadNonce)
	if !ok1 || !ok2 {
		return fmt.Errorf("ikev1: MM4 missing KE or Nonce")
	}
	s.peerPub = append([]byte(nil), ke.body...)
	s.nr = append([]byte(nil), nc.body...)
	if err := s.deriveKeys(); err != nil {
		return err
	}
	// Initiator: g^xi is our public, g^xr the peer's.
	s.keys.setInitialIV(s.localPub, s.peerPub)
	s.advance()

	// Float before MM5: from here on both ends are on the NAT-T port.
	if s.peerNATT {
		s.float(payloads)
	}

	s.idI = buildID(s.localIdentity())
	hashI := s.keys.hashI(s.localPub, s.peerPub, s.initCookie, s.respCookie, s.saBodyI, s.idI)
	s.state = stWaitMM6
	return s.sendEncrypted(exchangeMain, 0, &s.keys.iv, []payload{
		{typ: payloadID, body: s.idI},
		{typ: payloadHash, body: hashI},
	})
}

func (s *Session) initHandleMM6(first uint8, rest []byte) error {
	payloads, _, _, err := s.recvDecrypt(&s.keys.iv, first, rest)
	if err != nil {
		return err
	}
	id, ok1 := findPayload(payloads, payloadID)
	hp, ok2 := findPayload(payloads, payloadHash)
	if !ok1 || !ok2 {
		return fmt.Errorf("ikev1: MM6 missing ID or HASH")
	}
	s.idR = append([]byte(nil), id.body...)
	want := s.keys.hashR(s.localPub, s.peerPub, s.initCookie, s.respCookie, s.saBodyI, s.idR)
	if !constEq(want, hp.body) {
		return fmt.Errorf("%w: HASH_R verification failed (bad PSK?)", ErrAuth)
	}
	s.advance()
	return s.afterPhase1()
}

// startQuickMode sends QM1 (HASH(1), SA, Ni, IDci, IDcr) as the initiator.
func (s *Session) startQuickMode() error {
	s.qmMsgID = randSPI() // any nonzero message ID
	s.qmIV = s.keys.quickModeIV(s.qmMsgID)
	s.qmNi = nonce()
	s.inSPI = randSPI()
	props := s.defaultESPProposals()
	s.esp = props[0]

	local, remote, err := s.phase2Selectors()
	if err != nil {
		return err
	}
	content := []payload{
		{typ: payloadSA, body: buildPhase2SA(s.inSPI, props)},
		{typ: payloadNonce, body: s.qmNi},
		{typ: payloadID, body: buildID(local)},
		{typ: payloadID, body: buildID(remote)},
	}
	_, contentChain := payloadChain(content)
	hash1 := s.keys.prf.Apply(s.keys.skeyidA, concat(be32(s.qmMsgID), contentChain))

	payloads := append([]payload{{typ: payloadHash, body: hash1}}, content...)
	s.state = stWaitQM2
	return s.sendEncrypted(exchangeQuick, s.qmMsgID, &s.qmIV, payloads)
}

func (s *Session) initHandleQM2(first uint8, rest []byte) error {
	payloads, plain, consumed, err := s.recvDecrypt(&s.qmIV, first, rest)
	if err != nil {
		return err
	}
	hp, ok := findPayload(payloads, payloadHash)
	if !ok {
		return fmt.Errorf("ikev1: QM2 missing HASH")
	}
	sa, ok := findPayload(payloads, payloadSA)
	nc, ok2 := findPayload(payloads, payloadNonce)
	if !ok || !ok2 {
		return fmt.Errorf("ikev1: QM2 missing SA or Nonce")
	}
	s.qmNr = append([]byte(nil), nc.body...)

	// HASH(2) = prf(SKEYID_a, M-ID | Ni_b | <payloads after HASH>).
	rawContent := afterHash(plain, payloads, consumed)
	want := s.keys.prf.Apply(s.keys.skeyidA, concat(be32(s.qmMsgID), s.qmNi, rawContent))
	if !constEq(want, hp.body) {
		return fmt.Errorf("ikev1: QM HASH(2) verification failed")
	}

	proto, spi, transforms, err := parseSA(sa.body)
	if err != nil {
		return err
	}
	if proto != protoESP || len(spi) != 4 || len(transforms) != 1 {
		return fmt.Errorf("ikev1: QM2 SA malformed")
	}
	esp, ok := espPropFromAttrs(transforms[0].id, transforms[0].attrs)
	if !ok || !s.supportedESP(esp) {
		return fmt.Errorf("ikev1: responder chose an unsupported ESP proposal")
	}
	s.esp = esp
	s.outSPI = be32ToU32(spi)

	// HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b).
	hash3 := s.keys.prf.Apply(s.keys.skeyidA, concat([]byte{0}, be32(s.qmMsgID), s.qmNi, s.qmNr))
	s.advance()
	if err := s.sendEncrypted(exchangeQuick, s.qmMsgID, &s.qmIV, []payload{{typ: payloadHash, body: hash3}}); err != nil {
		return err
	}
	s.finish()
	return nil
}

// --- responder ---

func (s *Session) dispatchResponder(h header, first uint8, rest []byte) error {
	switch s.state {
	case stInit:
		if s.cfg.Mode == ModeAggressive {
			return s.respHandleAM1(h, first, rest)
		}
		return s.respHandleMM1(h, first, rest)
	case stWaitMM3:
		return s.respHandleMM3(first, rest)
	case stWaitMM5:
		return s.respHandleMM5(first, rest)
	case stWaitAM3:
		return s.respHandleAM3(first, rest)
	case stWaitXAuthRep, stWaitXAuthAck, stWaitCfgReq:
		return s.handleTransaction(h, first, rest)
	case stWaitQM1:
		return s.respHandleQM1(h, first, rest)
	case stWaitQM3:
		return s.respHandleQM3(first, rest)
	}
	return nil
}

func (s *Session) respHandleMM1(h header, first uint8, rest []byte) error {
	s.initCookie = h.initCookie
	_, _ = randRead(s.respCookie[:])
	payloads, _, err := parsePayloads(first, rest)
	if err != nil {
		return err
	}
	sa, ok := findPayload(payloads, payloadSA)
	if !ok {
		return fmt.Errorf("ikev1: MM1 without SA")
	}
	s.saBodyI = append([]byte(nil), sa.body...) // initiator's SA body, for HASH
	_, _, transforms, err := parseSA(sa.body)
	if err != nil {
		return err
	}
	prop, num, ok := s.selectIKEProposal(transforms)
	if !ok {
		return fmt.Errorf("ikev1: no acceptable IKE proposal offered")
	}
	s.prop = prop
	s.propNum = num
	s.peerNATT = peerSupportsNATT(payloads)
	if !s.peerNATT {
		return errNoNATT
	}

	chosen := buildPhase1SAChosen(num, prop)
	mm2 := []payload{{typ: payloadSA, body: chosen}}
	if s.peerNATT {
		// Echo NAT-T support only if the initiator offered it, so a peer that
		// cannot float is not told we expect it to.
		mm2 = append(mm2, natTVendorPayloads()...)
	}
	msg := marshalMessage(s.mmHeader(exchangeMain, 0, 0), mm2)
	s.state = stWaitMM3
	return s.transmit(msg)
}

func (s *Session) respHandleMM3(first uint8, rest []byte) error {
	payloads, _, err := parsePayloads(first, rest)
	if err != nil {
		return err
	}
	ke, ok1 := findPayload(payloads, payloadKE)
	nc, ok2 := findPayload(payloads, payloadNonce)
	if !ok1 || !ok2 {
		return fmt.Errorf("ikev1: MM3 missing KE or Nonce")
	}
	s.peerPub = append([]byte(nil), ke.body...)
	s.ni = append([]byte(nil), nc.body...)

	dh, err := dhGroup(s.prop.group)
	if err != nil {
		return err
	}
	s.dh = dh
	s.localPub, err = dh.Generate()
	if err != nil {
		return err
	}
	s.nr = nonce()
	if err := s.deriveKeys(); err != nil {
		return err
	}
	// Responder: g^xi is the peer's public, g^xr ours.
	s.keys.setInitialIV(s.peerPub, s.localPub)
	s.advance()

	mm4 := []payload{
		{typ: payloadKE, body: s.localPub},
		{typ: payloadNonce, body: s.nr},
	}
	if s.peerNATT {
		mm4 = append(mm4, s.natdPayloads()...)
	}
	msg := marshalMessage(s.mmHeader(exchangeMain, 0, 0), mm4)
	s.state = stWaitMM5
	if err := s.transmit(msg); err != nil {
		return err
	}
	// MM4 goes out on the old port; everything after it — starting with the MM5
	// we now expect — is on the NAT-T port.
	if s.peerNATT {
		s.float(payloads)
	}
	return nil
}

func (s *Session) respHandleMM5(first uint8, rest []byte) error {
	payloads, _, _, err := s.recvDecrypt(&s.keys.iv, first, rest)
	if err != nil {
		return err
	}
	id, ok1 := findPayload(payloads, payloadID)
	hp, ok2 := findPayload(payloads, payloadHash)
	if !ok1 || !ok2 {
		return fmt.Errorf("ikev1: MM5 missing ID or HASH")
	}
	s.idI = append([]byte(nil), id.body...)
	want := s.keys.hashI(s.peerPub, s.localPub, s.initCookie, s.respCookie, s.saBodyI, s.idI)
	if !constEq(want, hp.body) {
		return fmt.Errorf("%w: HASH_I verification failed (bad PSK?)", ErrAuth)
	}
	s.advance()

	s.idR = buildID(s.localIdentity())
	hashR := s.keys.hashR(s.peerPub, s.localPub, s.initCookie, s.respCookie, s.saBodyI, s.idR)
	if err := s.sendEncrypted(exchangeMain, 0, &s.keys.iv, []payload{
		{typ: payloadID, body: s.idR},
		{typ: payloadHash, body: hashR},
	}); err != nil {
		return err
	}
	return s.afterPhase1()
}

func (s *Session) respHandleQM1(h header, first uint8, rest []byte) error {
	s.qmMsgID = h.messageID
	s.qmIV = s.keys.quickModeIV(s.qmMsgID)
	payloads, plain, consumed, err := s.recvDecrypt(&s.qmIV, first, rest)
	if err != nil {
		return err
	}
	hp, ok := findPayload(payloads, payloadHash)
	sa, ok2 := findPayload(payloads, payloadSA)
	nc, ok3 := findPayload(payloads, payloadNonce)
	if !ok || !ok2 || !ok3 {
		return fmt.Errorf("ikev1: QM1 missing HASH, SA or Nonce")
	}
	s.qmNi = append([]byte(nil), nc.body...)

	rawContent := afterHash(plain, payloads, consumed)
	want := s.keys.prf.Apply(s.keys.skeyidA, concat(be32(s.qmMsgID), rawContent))
	if !constEq(want, hp.body) {
		return fmt.Errorf("ikev1: QM HASH(1) verification failed")
	}

	proto, spi, transforms, err := parseSA(sa.body)
	if err != nil {
		return err
	}
	if proto != protoESP || len(spi) != 4 {
		return fmt.Errorf("ikev1: QM1 SA malformed")
	}
	esp, num, ok := s.selectESPProposal(transforms)
	if !ok {
		return fmt.Errorf("ikev1: no acceptable ESP proposal offered")
	}
	s.esp = esp
	s.outSPI = be32ToU32(spi) // initiator's inbound SPI: our outbound
	s.inSPI = randSPI()
	s.qmNr = nonce()
	s.advance()

	// QM2: HASH(2), SA (our inbound SPI, the chosen transform), Nr, IDci, IDcr.
	content := []payload{
		{typ: payloadSA, body: buildPhase2SA(s.inSPI, []espProposal{withNum(esp, num)})},
		{typ: payloadNonce, body: s.qmNr},
	}
	// Echo the two traffic-selector IDs if present.
	for _, p := range payloads {
		if p.typ == payloadID {
			content = append(content, payload{typ: payloadID, body: append([]byte(nil), p.body...)})
		}
	}
	_, contentChain := payloadChain(content)
	hash2 := s.keys.prf.Apply(s.keys.skeyidA, concat(be32(s.qmMsgID), s.qmNi, contentChain))
	msg := append([]payload{{typ: payloadHash, body: hash2}}, content...)
	s.state = stWaitQM3
	return s.sendEncrypted(exchangeQuick, s.qmMsgID, &s.qmIV, msg)
}

func (s *Session) respHandleQM3(first uint8, rest []byte) error {
	payloads, _, _, err := s.recvDecrypt(&s.qmIV, first, rest)
	if err != nil {
		return err
	}
	hp, ok := findPayload(payloads, payloadHash)
	if !ok {
		return fmt.Errorf("ikev1: QM3 missing HASH")
	}
	want := s.keys.prf.Apply(s.keys.skeyidA, concat([]byte{0}, be32(s.qmMsgID), s.qmNi, s.qmNr))
	if !constEq(want, hp.body) {
		return fmt.Errorf("ikev1: QM HASH(3) verification failed")
	}
	s.advance()
	s.finish()
	return nil
}

// withNum returns a copy of the ESP proposal — the number is set by the SA
// builder's transform index, so this is a passthrough kept for symmetry with the
// selection API.
func withNum(p espProposal, _ uint8) espProposal { return p }
