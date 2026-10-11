package ikev1

// The ISAKMP Transaction exchange (type 6) and its Attribute payload (type 14).
//
//	HDR*, HASH(1), ATTR
//
// One exchange, two protocols. XAuth (draft-ietf-ipsec-isakmp-xauth-06) runs
// first, pushed by the gateway: it asks for a username and password, then
// reports the verdict and waits to be acknowledged. Mode-Config
// (draft-dukes-ike-mode-cfg) runs second, pulled by the client: it asks for an
// address and gets one back. They are the same message with different attribute
// numbers, which is why they share this file.
//
// Each request/answer pair carries its own message ID, and each message ID has
// its own CBC chain seeded from the last phase-1 block — the same rule Quick
// Mode follows. The HASH is computed exactly as Quick Mode's HASH(1) is:
// prf(SKEYID_a, M-ID | everything after the HASH payload).

import (
	"encoding/binary"
	"fmt"
	"net"
)

// cfgPayload is a decoded Attribute payload body: a message type, an identifier
// echoed by the answer, and the attributes themselves.
type cfgPayload struct {
	typ        uint8
	identifier uint16
	attrs      []attr
}

// cfgHeaderLen is Type(1) | RESERVED(1) | Identifier(2).
const cfgHeaderLen = 4

func buildCfg(c cfgPayload) []byte {
	body := make([]byte, cfgHeaderLen)
	body[0] = c.typ
	binary.BigEndian.PutUint16(body[2:], c.identifier)
	return append(body, encodeAttrs(c.attrs)...)
}

func parseCfg(body []byte) (cfgPayload, error) {
	if len(body) < cfgHeaderLen {
		return cfgPayload{}, fmt.Errorf("ikev1: attribute payload shorter than its header")
	}
	attrs, err := parseAttrs(body[cfgHeaderLen:])
	if err != nil {
		return cfgPayload{}, err
	}
	return cfgPayload{
		typ:        body[0],
		identifier: binary.BigEndian.Uint16(body[2:4]),
		attrs:      attrs,
	}, nil
}

// txIVFor returns the CBC chain for a Transaction message ID, seeding a fresh
// one when the ID changes. Reusing the chain within an ID is what lets a
// request and its answer decrypt; reseeding across IDs is what keeps two
// exchanges in flight from corrupting each other.
func (s *Session) txIVFor(msgID uint32) *[]byte {
	if s.txIV == nil || s.txMsgID != msgID {
		s.txMsgID = msgID
		s.txIV = s.keys.quickModeIV(msgID)
	}
	return &s.txIV
}

// sendTransaction encrypts and sends one Transaction message under msgID.
func (s *Session) sendTransaction(msgID uint32, c cfgPayload) error {
	content := []payload{{typ: payloadAttribute, body: buildCfg(c)}}
	_, chain := payloadChain(content)
	hash := s.keys.prf.Apply(s.keys.skeyidA, concat(be32(msgID), chain))
	msg := append([]payload{{typ: payloadHash, body: hash}}, content...)
	return s.sendEncrypted(exchangeTransaction, msgID, s.txIVFor(msgID), msg)
}

// recvTransaction decrypts one Transaction message and verifies its HASH.
func (s *Session) recvTransaction(h header, first uint8, rest []byte) (cfgPayload, error) {
	payloads, plain, consumed, err := s.recvDecrypt(s.txIVFor(h.messageID), first, rest)
	if err != nil {
		return cfgPayload{}, err
	}
	hp, ok := findPayload(payloads, payloadHash)
	if !ok {
		return cfgPayload{}, fmt.Errorf("ikev1: Transaction message without HASH")
	}
	want := s.keys.prf.Apply(s.keys.skeyidA, concat(be32(h.messageID), afterHash(plain, payloads, consumed)))
	if !constEq(want, hp.body) {
		return cfgPayload{}, fmt.Errorf("ikev1: Transaction HASH verification failed")
	}
	ap, ok := findPayload(payloads, payloadAttribute)
	if !ok {
		return cfgPayload{}, fmt.Errorf("ikev1: Transaction message without an Attribute payload")
	}
	return parseCfg(ap.body)
}

// --- XAuth ---

// sendXAuthRequest asks the initiator for its credentials. The gateway drives
// this, so it also picks the message ID and the identifier the answer echoes.
func (s *Session) sendXAuthRequest() error {
	s.txID = uint16(randSPI())
	s.state = stWaitXAuthRep
	return s.sendTransaction(randSPI(), cfgPayload{
		typ:        cfgRequest,
		identifier: s.txID,
		attrs: []attr{
			basicAttr(xauthType, xauthTypeGeneric),
			// Empty values are the question: the initiator fills them in.
			varAttr(xauthUserName, nil),
			varAttr(xauthUserPassword, nil),
		},
	})
}

// initHandleXAuthRequest answers a credential request.
func (s *Session) initHandleXAuthRequest(msgID uint32, c cfgPayload) error {
	if s.cfg.XAuth == nil {
		return fmt.Errorf("ikev1: peer asked for XAuth, which is not configured")
	}
	if a, ok := findAttr(c.attrs, xauthMessage); ok && len(a.value) > 0 {
		s.logger.Printf("ikev1: XAuth message from peer: %q", string(a.value))
	}
	if _, ok := findAttr(c.attrs, xauthChallenge); ok {
		return fmt.Errorf("ikev1: the gateway asked for a challenge response, which veepin cannot answer")
	}
	s.state = stWaitXAuthSet
	return s.sendTransaction(msgID, cfgPayload{
		typ:        cfgReply,
		identifier: c.identifier,
		attrs: []attr{
			basicAttr(xauthType, xauthTypeGeneric),
			varAttr(xauthUserName, []byte(s.cfg.XAuth.Username)),
			varAttr(xauthUserPassword, []byte(s.cfg.XAuth.Password)),
		},
	})
}

// respHandleXAuthReply checks the credentials and pushes the verdict.
//
// A rejection is reported to the peer before the session fails, so the client
// can say "wrong password" rather than "the gateway stopped answering".
func (s *Session) respHandleXAuthReply(c cfgPayload) error {
	user, _ := findAttr(c.attrs, xauthUserName)
	pass, _ := findAttr(c.attrs, xauthUserPassword)
	ok := s.cfg.XAuth != nil && s.cfg.XAuth.Authenticate != nil &&
		s.cfg.XAuth.Authenticate(string(user.value), string(pass.value))

	status := uint16(xauthStatusOK)
	if !ok {
		status = xauthStatusFail
	}
	s.txID = uint16(randSPI())
	s.state = stWaitXAuthAck
	if err := s.sendTransaction(randSPI(), cfgPayload{
		typ:        cfgSet,
		identifier: s.txID,
		attrs:      []attr{basicAttr(xauthStatus, status)},
	}); err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: XAuth rejected user %q", ErrAuth, string(user.value))
	}
	// Authentication is complete the moment the verdict is sent, not when the
	// acknowledgement comes back. The client sends its acknowledgement and its
	// configuration request back to back, and those two can arrive in either
	// order; making the request wait on the acknowledgement would turn ordinary
	// datagram reordering into a failed session.
	s.xauthDone = true
	s.xauthUser = string(user.value)
	s.logger.Printf("ikev1: XAuth accepted user %q", s.xauthUser)
	return nil
}

// initHandleXAuthSet acknowledges the verdict and, when it was a pass, moves on
// to Mode-Config.
func (s *Session) initHandleXAuthSet(msgID uint32, c cfgPayload) error {
	a, ok := findAttr(c.attrs, xauthStatus)
	if !ok {
		return fmt.Errorf("ikev1: XAuth SET without a status")
	}
	status, ok := attrUint16(a)
	if !ok {
		return fmt.Errorf("ikev1: XAuth status is not a basic attribute")
	}
	// The acknowledgement goes out even for a failure: it is what tells the
	// gateway the verdict arrived, and it costs nothing to be well-behaved on
	// the way out.
	if err := s.sendTransaction(msgID, cfgPayload{
		typ:        cfgAck,
		identifier: c.identifier,
		attrs:      []attr{basicAttr(xauthStatus, status)},
	}); err != nil {
		return err
	}
	if status != xauthStatusOK {
		return fmt.Errorf("%w: XAuth rejected the password", ErrAuth)
	}
	s.xauthDone = true
	if s.cfg.ModeCfg {
		return s.sendCfgRequest()
	}
	return s.startQuickMode()
}

// respHandleXAuthAck notes that the client saw the verdict. It only advances the
// state: xauthDone was set when the verdict went out, so a request that
// overtook this acknowledgement has already been answered.
func (s *Session) respHandleXAuthAck() error {
	if s.cfg.ModeCfg {
		s.state = stWaitCfgReq
		return nil
	}
	s.state = stWaitQM1
	return nil
}

// --- Mode-Config ---

// modeCfgRetries bounds how many configuration requests a responder will answer
// for one session. A client that keeps asking is either confused or trying to
// make the gateway allocate repeatedly; one spare attempt covers a lost reply.
const modeCfgRetries = 3

// sendCfgRequest pulls the inner configuration. The attributes are sent empty:
// their presence is the question, and the reply fills them in.
func (s *Session) sendCfgRequest() error {
	s.txID = uint16(randSPI())
	s.state = stWaitCfgRep
	return s.sendTransaction(randSPI(), cfgPayload{
		typ:        cfgRequest,
		identifier: s.txID,
		attrs: []attr{
			varAttr(cfgAttrIP4Address, nil),
			varAttr(cfgAttrIP4Netmask, nil),
			varAttr(cfgAttrIP4DNS, nil),
			varAttr(cfgAttrIP4NBNS, nil),
			varAttr(cfgAttrAppVersion, []byte(appVersion)),
			varAttr(unityBanner, nil),
			varAttr(unityDefDomain, nil),
			varAttr(unitySplitInclude, nil),
		},
	})
}

// appVersion is the free-text version string both roles put in
// APPLICATION_VERSION. Gateways log it, and some clients display it.
const appVersion = "veepin IPsec"

// respHandleCfgRequest assigns the configuration and replies with it.
func (s *Session) respHandleCfgRequest(msgID uint32, c cfgPayload) error {
	if !s.xauthDone {
		return fmt.Errorf("ikev1: configuration requested before authentication")
	}
	s.cfgAttempt++
	if s.cfgAttempt > modeCfgRetries {
		return fmt.Errorf("ikev1: too many configuration requests")
	}
	if s.assigned == nil {
		if s.cfg.Assign == nil {
			return fmt.Errorf("ikev1: no address assignment configured")
		}
		cfg, err := s.cfg.Assign()
		if err != nil {
			return err
		}
		s.assigned = &cfg
	}
	if a, ok := findAttr(c.attrs, cfgAttrAppVersion); ok && len(a.value) > 0 {
		s.logger.Printf("ikev1: peer application version %q", string(a.value))
	}
	s.state = stWaitQM1
	return s.sendTransaction(msgID, cfgPayload{
		typ:        cfgReply,
		identifier: c.identifier,
		attrs:      cfgReplyAttrs(*s.assigned),
	})
}

// cfgReplyAttrs renders an assignment as Mode-Config and Unity attributes.
// Only what was actually assigned is sent: an empty attribute in a reply reads
// as "nothing here" to some clients and as a zero value to others, and omitting
// it is unambiguous to both.
func cfgReplyAttrs(r ModeCfgReply) []attr {
	var attrs []attr
	if v4 := r.Address.To4(); v4 != nil {
		attrs = append(attrs, varAttr(cfgAttrIP4Address, v4))
	}
	if len(r.Netmask) > 0 {
		if v4 := net.IP(r.Netmask).To4(); v4 != nil {
			attrs = append(attrs, varAttr(cfgAttrIP4Netmask, v4))
		}
	}
	for _, d := range r.DNS {
		if v4 := d.To4(); v4 != nil {
			attrs = append(attrs, varAttr(cfgAttrIP4DNS, v4))
		}
	}
	for _, n := range r.NBNS {
		if v4 := n.To4(); v4 != nil {
			attrs = append(attrs, varAttr(cfgAttrIP4NBNS, v4))
		}
	}
	attrs = append(attrs, varAttr(cfgAttrAppVersion, []byte(appVersion)))
	if r.Banner != "" {
		attrs = append(attrs, varAttr(unityBanner, []byte(r.Banner)))
	}
	if r.Domain != "" {
		attrs = append(attrs, varAttr(unityDefDomain, []byte(r.Domain)))
	}
	for _, n := range r.SplitInclude {
		if v := encodeSplitInclude(n); v != nil {
			attrs = append(attrs, varAttr(unitySplitInclude, v))
		}
	}
	return attrs
}

// splitIncludeLen is the fixed size of one UNITY_SPLIT_INCLUDE entry: an IPv4
// network and mask followed by ten octets Cisco reserves for a protocol/port
// selector veepin does not use.
const splitIncludeLen = 14

// encodeSplitInclude renders one split-tunnel network. A non-IPv4 network, or
// one whose mask is not a contiguous IPv4 mask, has no representation here and
// is skipped rather than sent wrong.
func encodeSplitInclude(n *net.IPNet) []byte {
	if n == nil {
		return nil
	}
	ip := n.IP.To4()
	if ip == nil || len(n.Mask) != net.IPv4len {
		return nil
	}
	out := make([]byte, splitIncludeLen)
	copy(out[0:4], ip)
	copy(out[4:8], n.Mask)
	return out
}

// parseSplitInclude reads one split-tunnel network back.
func parseSplitInclude(v []byte) *net.IPNet {
	if len(v) < 8 {
		return nil
	}
	return &net.IPNet{
		IP:   net.IPv4(v[0], v[1], v[2], v[3]).To4(),
		Mask: net.IPv4Mask(v[4], v[5], v[6], v[7]),
	}
}

// initHandleCfgReply applies the assignment and starts Quick Mode, whose
// traffic selector is the address it just learned.
func (s *Session) initHandleCfgReply(c cfgPayload) error {
	r := parseCfgReply(c)
	if r.Address == nil {
		return fmt.Errorf("ikev1: the gateway assigned no address")
	}
	s.assigned = &r
	if r.Banner != "" {
		s.logger.Printf("ikev1: gateway banner: %s", r.Banner)
	}
	s.logger.Printf("ikev1: assigned %s", r.Address)
	return s.startQuickMode()
}

// parseCfgReply decodes an assignment. Attributes it does not recognise are
// ignored, which is what lets a gateway send its whole vendor block.
func parseCfgReply(c cfgPayload) ModeCfgReply {
	var r ModeCfgReply
	for _, a := range c.attrs {
		switch a.typ {
		case cfgAttrIP4Address:
			if len(a.value) == net.IPv4len {
				r.Address = net.IP(append([]byte(nil), a.value...)).To4()
			}
		case cfgAttrIP4Netmask:
			if len(a.value) == net.IPv4len {
				r.Netmask = net.IP(append([]byte(nil), a.value...)).To4()
			}
		case cfgAttrIP4DNS:
			if len(a.value) == net.IPv4len {
				r.DNS = append(r.DNS, net.IP(append([]byte(nil), a.value...)).To4())
			}
		case cfgAttrIP4NBNS:
			if len(a.value) == net.IPv4len {
				r.NBNS = append(r.NBNS, net.IP(append([]byte(nil), a.value...)).To4())
			}
		case cfgAttrAppVersion:
			r.AppVersion = string(a.value)
		case unityBanner:
			r.Banner = string(a.value)
		case unityDefDomain:
			r.Domain = string(a.value)
		case unitySplitInclude:
			if n := parseSplitInclude(a.value); n != nil {
				r.SplitInclude = append(r.SplitInclude, n)
			}
		}
	}
	return r
}

// --- dispatch ---

// handleTransaction routes one Transaction message by what it is rather than by
// what the state machine expected. XAuth and Mode-Config are four exchanges
// back to back, and a peer that repeats one — a lost reply, a gateway that asks
// twice — is answered rather than treated as a protocol violation.
func (s *Session) handleTransaction(h header, first uint8, rest []byte) error {
	c, err := s.recvTransaction(h, first, rest)
	if err != nil {
		return err
	}
	if s.cfg.Role == Initiator {
		switch c.typ {
		case cfgRequest:
			return s.initHandleXAuthRequest(h.messageID, c)
		case cfgSet:
			return s.initHandleXAuthSet(h.messageID, c)
		case cfgReply:
			return s.initHandleCfgReply(c)
		}
		return fmt.Errorf("ikev1: unexpected Transaction type %d from the gateway", c.typ)
	}
	switch c.typ {
	case cfgReply:
		return s.respHandleXAuthReply(c)
	case cfgAck:
		return s.respHandleXAuthAck()
	case cfgRequest:
		return s.respHandleCfgRequest(h.messageID, c)
	}
	return fmt.Errorf("ikev1: unexpected Transaction type %d from the client", c.typ)
}
