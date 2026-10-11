package ikev1

// Aggressive Mode (RFC 2409 section 5.4): phase 1 in three messages instead of
// six.
//
//	Initiator                        Responder
//	HDR, SA, KE, Ni, IDii    -->
//	                         <--     HDR, SA, KE, Nr, IDir, HASH_R
//	HDR*, HASH_I             -->
//
// Everything but the last message is in the clear, identities included. That is
// the trade the mode exists to make, and it is why every remote-access
// deployment pairs it with XAuth: the identity exposed is a shared group name,
// not a user's, and the real credentials travel afterwards under phase-1
// encryption.
//
// The keying is otherwise identical to Main Mode — the same SKEYID family, the
// same HASH_I/HASH_R over the same inputs — so this file is the message layout
// and nothing more. Both ends have everything they need after two messages,
// which is also why the responder can put HASH_R in the same message as its
// nonce.

import (
	"fmt"
	"net"
)

// keyIDIdentity is the phase-1 identity Aggressive Mode carries for a
// remote-access group: an opaque octet string, which is what Cisco-style
// gateways match their group pre-shared key on.
func keyIDIdentity(group string) identity {
	return identity{idType: idKeyID, data: []byte(group)}
}

// groupNameOf reads the group name back out of an Identification payload body.
// Any ID type is accepted: the responder's job is to hand whatever the initiator
// named to the PSK lookup, not to insist on a spelling.
func groupNameOf(idBody []byte) string {
	if len(idBody) < 4 {
		return ""
	}
	return string(idBody[4:])
}

// localIdentity is the identity this end presents in phase 1: the configured
// group name where there is one, otherwise the local address, which is what
// Main Mode has always sent.
func (s *Session) localIdentity() identity {
	if s.cfg.GroupName != "" {
		return keyIDIdentity(s.cfg.GroupName)
	}
	return ipv4ID(s.cfg.LocalIP)
}

// authMethod is the phase-1 authentication method this profile negotiates.
// Offering XAUTHInitPreShared rather than plain PSK is how both ends agree that
// extended authentication runs before phase 2; the keying is the same either
// way.
func (s *Session) authMethod() uint16 {
	if s.cfg.XAuth != nil {
		return authXAuthInitPSK
	}
	return authPSK
}

// --- initiator ---

// sendAM1 opens Aggressive Mode. Unlike Main Mode the key exchange is in the
// first message, so the group cannot be the one the responder selects — it is
// the group of the offered proposals, all of which use the same one.
func (s *Session) sendAM1() error {
	props := defaultIKEProposals(s.authMethod())
	s.prop = props[0] // provisional: only the hash can differ, and AM2 pins it
	dh, err := dhGroup(s.prop.group)
	if err != nil {
		return err
	}
	s.dh = dh
	if s.localPub, err = dh.Generate(); err != nil {
		return err
	}
	s.ni = nonce()
	s.saBodyI = buildPhase1SA(props)
	s.idI = buildID(s.localIdentity())

	payloads := append([]payload{
		{typ: payloadSA, body: s.saBodyI},
		{typ: payloadKE, body: s.localPub},
		{typ: payloadNonce, body: s.ni},
		{typ: payloadID, body: s.idI},
	}, natTVendorPayloads()...)
	return s.transmit(marshalMessage(s.mmHeader(exchangeAggressive, 0, 0), payloads))
}

func (s *Session) initHandleAM2(h header, first uint8, rest []byte) error {
	s.respCookie = h.respCookie
	payloads, _, err := parsePayloads(first, rest)
	if err != nil {
		return err
	}
	sa, ok := findPayload(payloads, payloadSA)
	if !ok {
		return fmt.Errorf("ikev1: AM2 without SA")
	}
	_, _, transforms, err := parseSA(sa.body)
	if err != nil {
		return err
	}
	if len(transforms) != 1 {
		return fmt.Errorf("ikev1: AM2 must choose exactly one transform")
	}
	prop, ok := ikePropFromAttrs(transforms[0].attrs)
	if !ok || !s.supportedIKE(prop) {
		return fmt.Errorf("ikev1: responder chose an unsupported IKE proposal")
	}
	if prop.group != s.prop.group {
		// The key exchange already happened under the offered group, so a
		// responder that selects a different one has produced a public value we
		// cannot combine with ours.
		return fmt.Errorf("ikev1: responder chose group %d after AM1 offered %d", prop.group, s.prop.group)
	}
	s.prop = prop
	s.peerNATT = peerSupportsNATT(payloads)
	if !s.peerNATT {
		return errNoNATT
	}

	ke, ok1 := findPayload(payloads, payloadKE)
	nc, ok2 := findPayload(payloads, payloadNonce)
	id, ok3 := findPayload(payloads, payloadID)
	hp, ok4 := findPayload(payloads, payloadHash)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return fmt.Errorf("ikev1: AM2 missing KE, Nonce, ID or HASH")
	}
	s.peerPub = append([]byte(nil), ke.body...)
	s.nr = append([]byte(nil), nc.body...)
	s.idR = append([]byte(nil), id.body...)
	if err := s.deriveKeys(); err != nil {
		return err
	}
	s.keys.setInitialIV(s.localPub, s.peerPub)

	want := s.keys.hashR(s.localPub, s.peerPub, s.initCookie, s.respCookie, s.saBodyI, s.idR)
	if !constEq(want, hp.body) {
		return fmt.Errorf("%w: HASH_R verification failed (bad group password?)", ErrAuth)
	}
	s.advance()

	// AM3 is the first message on the NAT-T port, matching RFC 3947 section 4:
	// the NAT-D payloads it carries are the last of the detection exchange.
	s.float(payloads)

	hashI := s.keys.hashI(s.localPub, s.peerPub, s.initCookie, s.respCookie, s.saBodyI, s.idI)
	am3 := append([]payload{{typ: payloadHash, body: hashI}}, s.natdPayloads()...)
	if err := s.sendEncrypted(exchangeAggressive, 0, &s.keys.iv, am3); err != nil {
		return err
	}
	// Nothing acknowledges AM3 on its own: the responder's next message is
	// whatever the profile runs after phase 1.
	s.advance()
	return s.afterPhase1()
}

// --- responder ---

func (s *Session) respHandleAM1(h header, first uint8, rest []byte) error {
	s.initCookie = h.initCookie
	_, _ = randRead(s.respCookie[:])
	payloads, _, err := parsePayloads(first, rest)
	if err != nil {
		return err
	}
	sa, ok1 := findPayload(payloads, payloadSA)
	ke, ok2 := findPayload(payloads, payloadKE)
	nc, ok3 := findPayload(payloads, payloadNonce)
	id, ok4 := findPayload(payloads, payloadID)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return fmt.Errorf("ikev1: AM1 missing SA, KE, Nonce or ID")
	}
	s.saBodyI = append([]byte(nil), sa.body...)
	_, _, transforms, err := parseSA(sa.body)
	if err != nil {
		return err
	}
	prop, num, ok := s.selectIKEProposal(transforms)
	if !ok {
		return fmt.Errorf("ikev1: no acceptable IKE proposal offered")
	}
	s.prop, s.propNum = prop, num
	s.peerNATT = peerSupportsNATT(payloads)
	if !s.peerNATT {
		return errNoNATT
	}

	s.peerPub = append([]byte(nil), ke.body...)
	s.ni = append([]byte(nil), nc.body...)
	s.idI = append([]byte(nil), id.body...)

	// The group identity travels in the clear precisely so the key it selects is
	// available before anything is derived from it.
	if s.cfg.PSKFor != nil {
		psk, found := s.cfg.PSKFor(groupNameOf(s.idI))
		if !found {
			return fmt.Errorf("ikev1: no pre-shared key for group %q", groupNameOf(s.idI))
		}
		s.psk = psk
	}

	dh, err := dhGroup(s.prop.group)
	if err != nil {
		return err
	}
	s.dh = dh
	if s.localPub, err = dh.Generate(); err != nil {
		return err
	}
	s.nr = nonce()
	if err := s.deriveKeys(); err != nil {
		return err
	}
	s.keys.setInitialIV(s.peerPub, s.localPub)
	s.idR = buildID(s.localIdentity())
	hashR := s.keys.hashR(s.peerPub, s.localPub, s.initCookie, s.respCookie, s.saBodyI, s.idR)
	s.advance()

	am2 := []payload{
		{typ: payloadSA, body: buildPhase1SAChosen(num, prop)},
		{typ: payloadKE, body: s.localPub},
		{typ: payloadNonce, body: s.nr},
		{typ: payloadID, body: s.idR},
		{typ: payloadHash, body: hashR},
	}
	am2 = append(am2, s.natdPayloads()...)
	am2 = append(am2, natTVendorPayloads()...)

	s.state = stWaitAM3
	if err := s.transmit(marshalMessage(s.mmHeader(exchangeAggressive, 0, 0), am2)); err != nil {
		return err
	}
	// AM2 went out on the pre-float port; AM3 and everything after it arrive on
	// the NAT-T one.
	s.float(payloads)
	return nil
}

func (s *Session) respHandleAM3(first uint8, rest []byte) error {
	payloads, _, _, err := s.recvDecrypt(&s.keys.iv, first, rest)
	if err != nil {
		return err
	}
	hp, ok := findPayload(payloads, payloadHash)
	if !ok {
		return fmt.Errorf("ikev1: AM3 missing HASH")
	}
	want := s.keys.hashI(s.peerPub, s.localPub, s.initCookie, s.respCookie, s.saBodyI, s.idI)
	if !constEq(want, hp.body) {
		return fmt.Errorf("%w: HASH_I verification failed (bad group password?)", ErrAuth)
	}
	s.advance()
	return s.afterPhase1()
}

// afterPhase1 starts whatever the profile runs once phase 1 has authenticated:
// XAuth, then Mode-Config, then Quick Mode. A profile with neither — L2TP —
// goes straight to Quick Mode, which is what Main Mode has always done.
func (s *Session) afterPhase1() error {
	if s.cfg.Role == Initiator {
		switch {
		case s.cfg.XAuth != nil:
			// The responder drives XAuth; we wait for its request.
			s.state = stWaitXAuthReq
			return nil
		case s.cfg.ModeCfg:
			return s.sendCfgRequest()
		default:
			return s.startQuickMode()
		}
	}
	switch {
	case s.cfg.XAuth != nil:
		return s.sendXAuthRequest()
	case s.cfg.ModeCfg:
		s.xauthDone = true
		s.state = stWaitCfgReq
		return nil
	default:
		s.xauthDone = true
		s.state = stWaitQM1
		return nil
	}
}

// assignedIP is the inner address Mode-Config settled on, which the
// remote-access traffic selector names. It is nil for a profile without
// Mode-Config.
func (s *Session) assignedIP() net.IP {
	if s.assigned == nil {
		return nil
	}
	return s.assigned.Address
}
