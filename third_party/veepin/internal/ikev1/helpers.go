package ikev1

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

func be32ToU32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

// deriveKeys completes the DH exchange and derives the SKEYID family and phase-1
// encryption key for the negotiated suite.
func (s *Session) deriveKeys() error {
	shared, err := s.dh.ComputeSecret(s.peerPub)
	if err != nil {
		return err
	}
	prf, err := newPRF(s.prop.hash)
	if err != nil {
		return err
	}
	newHash, err := hashCtor(s.prop.hash)
	if err != nil {
		return err
	}
	s.keys = derivePhase1(prf, newHash, s.psk, s.ni, s.nr, shared, s.initCookie, s.respCookie, int(s.prop.keyBits)/8)
	return nil
}

// sendEncrypted encrypts a payload chain with the phase-1 key and the given IV
// (advancing it to the last cipher block), frames it with the Encryption flag,
// and transmits it.
func (s *Session) sendEncrypted(exchange uint8, msgID uint32, iv *[]byte, payloads []payload) error {
	first, chain := payloadChain(payloads)
	ct, err := cbcEncrypt(s.keys.encKey, *iv, chain)
	if err != nil {
		return err
	}
	*iv = lastBlock(ct)
	msg := assemble(s.mmHeader(exchange, flagEncryption, msgID), first, ct)
	return s.transmit(msg)
}

// recvDecrypt decrypts an inbound ciphertext with the given IV (advancing it),
// and parses the plaintext payload chain. It returns the parsed payloads, the
// decrypted plaintext, and the number of plaintext octets the chain occupied.
func (s *Session) recvDecrypt(iv *[]byte, first uint8, ct []byte) (payloads []payload, plain []byte, consumed int, err error) {
	plain, err = cbcDecrypt(s.keys.encKey, *iv, ct)
	if err != nil {
		return nil, nil, 0, err
	}
	*iv = lastBlock(ct)
	payloads, consumed, err = parsePayloads(first, plain)
	return payloads, plain, consumed, err
}

// afterHash returns the raw plaintext bytes following the leading HASH payload,
// bounded by the payload chain (excluding CBC padding). It is the content Quick
// Mode HASH(1)/HASH(2) authenticate.
func afterHash(plain []byte, payloads []payload, consumed int) []byte {
	if len(payloads) == 0 {
		return nil
	}
	hashLen := 4 + len(payloads[0].body)
	if hashLen > consumed || consumed > len(plain) {
		return nil
	}
	return plain[hashLen:consumed]
}

// finish derives the ESP keying material for both directions and reports the SA
// to the handler.
func (s *Session) finish() {
	encrID, keyLn, integID := espResultIDs(s.esp)
	encKeyLen := int(keyLn) / 8
	total := encKeyLen + integKeyLen(integID)

	outKM := s.keys.keymat(protoESP, be32(s.outSPI), s.qmNi, s.qmNr, total)
	inKM := s.keys.keymat(protoESP, be32(s.inSPI), s.qmNi, s.qmNr, total)

	r := Result{
		EncrID: encrID, EncrKeyLn: keyLn, IntegID: integID,
		OutSPI: s.outSPI, InSPI: s.inSPI, NATT: s.floated,
		OutEncKey: outKM[:encKeyLen], OutIntegKey: outKM[encKeyLen:],
		InEncKey: inKM[:encKeyLen], InIntegKey: inKM[encKeyLen:],
		Tunnel:  s.cfg.Phase2 == Phase2RemoteAccess,
		ModeCfg: s.assigned,
		User:    s.xauthUser,
	}
	s.state = stDone
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.cfg.Handler.Established(r)
}

// defaultESPProposals is what this session offers in Quick Mode, in the
// encapsulation mode its profile needs.
func (s *Session) defaultESPProposals() []espProposal {
	encap := uint16(encapUDPTransport)
	if s.cfg.Phase2 == Phase2RemoteAccess {
		encap = encapUDPTunnel
	}
	return []espProposal{
		{transformID: espTransformAES, keyBits: 256, authAlg: authHMACSHA2256, encap: encap, lifeSeconds: 3600},
		{transformID: espTransformAES, keyBits: 256, authAlg: authHMACSHA, encap: encap, lifeSeconds: 3600},
	}
}

// espResultIDs maps a negotiated ESP proposal to the IKEv2 transform IDs the
// internal/ikev2/esp data path consumes.
func espResultIDs(p espProposal) (encrID, keyLn, integID uint16) {
	encrID = espEncrAESCBC
	keyLn = p.keyBits
	if p.authAlg == authHMACSHA2256 {
		integID = espAuthHMACSHA256128
	} else {
		integID = espAuthHMACSHA196
	}
	return encrID, keyLn, integID
}

// --- proposal selection ---

func basicAttrOf(attrs []attr, typ uint16) (uint16, bool) {
	a, ok := findAttr(attrs, typ)
	if !ok {
		return 0, false
	}
	return attrUint16(a)
}

func ikePropFromAttrs(attrs []attr) (ikeProposal, bool) {
	enc, ok1 := basicAttrOf(attrs, attrEncryption)
	hsh, ok2 := basicAttrOf(attrs, attrHash)
	grp, ok3 := basicAttrOf(attrs, attrGroup)
	auth, ok4 := basicAttrOf(attrs, attrAuthMethod)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return ikeProposal{}, false
	}
	kb, _ := basicAttrOf(attrs, attrKeyLength)
	return ikeProposal{encr: enc, keyBits: kb, hash: hsh, group: grp, auth: auth, lifeSeconds: 3600}, true
}

// supportedIKE reports whether a phase-1 proposal is one this session will use.
//
// The authentication method is matched exactly rather than merely accepted:
// XAUTHInitPreShared and plain PSK key identically, so the only thing the number
// conveys is whether extended authentication follows. A peer that offers plain
// PSK to an XAuth profile would skip it, and a peer that offers XAuth to a
// profile with no credentials to give would stall — both are better refused
// here, where the reason is still legible.
func (s *Session) supportedIKE(p ikeProposal) bool {
	return p.encr == encrAES && p.keyBits == 256 &&
		(p.hash == hashSHA2256 || p.hash == hashSHA) &&
		p.group == groupMODP2048 && p.auth == s.authMethod()
}

func (s *Session) selectIKEProposal(transforms []parsedTransform) (ikeProposal, uint8, bool) {
	for _, t := range transforms {
		if p, ok := ikePropFromAttrs(t.attrs); ok && s.supportedIKE(p) {
			return p, t.num, true
		}
	}
	return ikeProposal{}, 0, false
}

func espPropFromAttrs(transformID uint8, attrs []attr) (espProposal, bool) {
	auth, ok := basicAttrOf(attrs, ipsecAttrAuthAlg)
	if !ok {
		return espProposal{}, false
	}
	encap, _ := basicAttrOf(attrs, ipsecAttrEncapMode)
	kb, _ := basicAttrOf(attrs, ipsecAttrKeyLength)
	return espProposal{transformID: transformID, keyBits: kb, authAlg: auth, encap: encap, lifeSeconds: 3600}, true
}

// supportedESP reports whether a phase-2 proposal matches the profile. The
// encapsulation mode is the discriminator: L2TP protects UDP/1701 in transport
// mode, remote access carries bare IP in tunnel mode, and accepting the wrong
// one would produce an SA whose packets the peer cannot parse.
func (s *Session) supportedESP(p espProposal) bool {
	var okEncap bool
	if s.cfg.Phase2 == Phase2RemoteAccess {
		okEncap = p.encap == encapUDPTunnel || p.encap == encapTunnel || p.encap == encapUDPTunnelDraft
	} else {
		okEncap = p.encap == encapUDPTransport || p.encap == encapTransport || p.encap == encapUDPTransportDraft
	}
	return p.transformID == espTransformAES && p.keyBits == 256 &&
		(p.authAlg == authHMACSHA2256 || p.authAlg == authHMACSHA) && okEncap
}

func (s *Session) selectESPProposal(transforms []parsedTransform) (espProposal, uint8, bool) {
	for _, t := range transforms {
		if p, ok := espPropFromAttrs(t.id, t.attrs); ok && s.supportedESP(p) {
			return p, t.num, true
		}
	}
	return espProposal{}, 0, false
}

// phase2Selectors are the traffic selectors Quick Mode names, local first.
//
// L2TP names exactly the UDP/1701 flow between the two outer addresses. Remote
// access names the client's assigned inner address against everything, which is
// the shape a gateway's policy is written in.
func (s *Session) phase2Selectors() (local, remote identity, err error) {
	if s.cfg.Phase2 != Phase2RemoteAccess {
		return l2tpSelector(s.cfg.LocalIP), l2tpSelector(s.cfg.PeerIP), nil
	}
	inner := s.assignedIP()
	if inner == nil {
		return identity{}, identity{}, fmt.Errorf("ikev1: no inner address for the phase-2 selector")
	}
	return ipv4ID(inner), anySubnetID(), nil
}
