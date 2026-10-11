package ikev1

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/cryptoutil"
	"github.com/xen0bit/veepin/internal/vlog"
)

// Role selects the IKE role: the Initiator drives Main Mode and Quick Mode, the
// Responder answers.
type Role int

const (
	Initiator Role = iota
	Responder
)

// nonceLen is the length of the phase-1 and phase-2 nonces (RFC 2409 allows
// 8..256 octets).
const nonceLen = 16

// ErrAuth marks the failures a wrong credential produces: the phase-1 hash a
// wrong pre-shared or group key cannot reproduce, and an XAuth status the
// gateway reported as a rejection. It exists so a caller can tell a bad password
// from a broken path, which are the two things a user most needs told apart.
var ErrAuth = errors.New("ikev1: authentication failed")

// ESP transform IDs as the internal/ikev2/esp data path expects them (IANA IKEv2
// values), mapped from the IKEv1 phase-2 negotiation.
const (
	espEncrAESCBC        = 12 // ENCR_AES_CBC
	espAuthHMACSHA196    = 2  // AUTH_HMAC_SHA1_96
	espAuthHMACSHA256128 = 12 // AUTH_HMAC_SHA2_256_128
)

// Result is the keyed ESP SA a completed exchange yields, oriented for the local
// end and expressed in the transform IDs internal/ikev2/esp consumes.
type Result struct {
	EncrID    uint16 // ESP encryption transform (IKEv2 ID)
	EncrKeyLn uint16 // encryption key length in bits
	IntegID   uint16 // ESP integrity transform (IKEv2 ID)

	OutSPI, InSPI          uint32
	OutEncKey, OutIntegKey []byte
	InEncKey, InIntegKey   []byte

	// NATT reports that the exchange floated to the NAT-T port, so ESP is
	// UDP-encapsulated there. veepin always negotiates this.
	NATT bool

	// Tunnel reports a tunnel-mode SA (remote access, carrying bare IP) rather
	// than the transport-mode SA L2TP runs over.
	Tunnel bool

	// ModeCfg is the inner configuration the Mode-Config exchange settled on,
	// or nil when the profile did not run one. The initiator receives what it
	// was assigned; the responder receives what it assigned.
	ModeCfg *ModeCfgReply

	// User is the XAuth username the exchange authenticated, empty when XAuth
	// did not run. A responder uses it to attribute the session.
	User string
}

// ModeCfgReply is the inner configuration Mode-Config carries: what a
// remote-access gateway assigns a client and the client then applies.
type ModeCfgReply struct {
	Address net.IP
	Netmask net.IP
	DNS     []net.IP
	NBNS    []net.IP

	// Banner, Domain and SplitInclude are the Cisco Unity attributes: a login
	// message, a default search domain, and the destinations to route into the
	// tunnel instead of taking a default route.
	Banner       string
	Domain       string
	SplitInclude []*net.IPNet

	// AppVersion is the peer's free-text version string, for logs.
	AppVersion string
}

// XAuthConfig parameters extended authentication. An initiator supplies the
// credentials it will send; a responder supplies the check they must pass.
type XAuthConfig struct {
	Username string
	Password string
	// Authenticate reports whether a username and password are acceptable
	// (responder). A nil check accepts nobody, which fails closed.
	Authenticate func(user, password string) bool
}

// Mode selects the phase-1 exchange.
type Mode int

const (
	// ModeMain is the six-message identity-protecting exchange (RFC 2409 5.1).
	ModeMain Mode = iota
	// ModeAggressive is the three-message exchange (RFC 2409 5.4). It sends the
	// identities in the clear, which is why every remote-access deployment pairs
	// it with XAuth: the identity it exposes is the shared group name, not the
	// user's.
	ModeAggressive
)

// Phase2Mode selects what the phase-2 SA protects.
type Phase2Mode int

const (
	// Phase2L2TP negotiates a transport-mode SA whose traffic selectors name
	// UDP/1701: exactly the L2TP datagrams, and nothing else.
	Phase2L2TP Phase2Mode = iota
	// Phase2RemoteAccess negotiates a tunnel-mode SA between the client's
	// assigned inner address and everything, carrying bare IP.
	Phase2RemoteAccess
)

// Handler receives the exchange outcome.
type Handler interface {
	Established(Result)
	Failed(error)
}

// Config parameters one IKE session.
type Config struct {
	Role Role
	// Mode is the phase-1 exchange; the zero value is Main Mode.
	Mode Mode
	// Phase2 is what the phase-2 SA protects; the zero value is L2TP transport
	// mode.
	Phase2 Phase2Mode
	PSK    []byte
	// GroupName is the remote-access group identity Aggressive Mode presents as
	// ID_KEY_ID. Empty leaves the identity as the local IP address, which is what
	// Main Mode uses.
	GroupName string
	// PSKFor selects the group's pre-shared key from the identity the initiator
	// presented (responder, Aggressive Mode). A nil lookup — or one that reports
	// false — falls back to PSK, so a single-group deployment need not set it.
	PSKFor func(group string) ([]byte, bool)
	// XAuth enables extended authentication after phase 1. Nil skips it.
	XAuth *XAuthConfig
	// ModeCfg enables the Mode-Config exchange between XAuth and Quick Mode. An
	// initiator pulls its address with it; a responder answers from Assign.
	ModeCfg bool
	// Assign supplies what the responder pushes in the Mode-Config reply. It is
	// called once per session, after XAuth has succeeded.
	Assign  func() (ModeCfgReply, error)
	LocalIP net.IP
	PeerIP  net.IP
	// LocalPort and PeerPort are the source and destination ports of the initial
	// (pre-float) IKE datagrams. They are hashed into the NAT-D payloads, so they
	// must be what the wire actually carries, not the well-known 500.
	LocalPort, PeerPort uint16
	// Send transmits one IKE datagram. natt reports whether the session has
	// floated: the transport then sends from the NAT-T port with the non-ESP
	// marker rather than the plain IKE port.
	Send    func(msg []byte, natt bool) error
	Handler Handler
	Logger  *vlog.Logger
}

type sessionState int

const (
	stInit sessionState = iota
	stWaitMM2
	stWaitMM3
	stWaitMM4
	stWaitMM5
	stWaitMM6
	stWaitAM2
	stWaitAM3
	// The Transaction states. XAuth runs first (the responder drives it), then
	// Mode-Config (the initiator pulls); each side names the message it is
	// waiting for.
	stWaitXAuthReq
	stWaitXAuthRep
	stWaitXAuthSet
	stWaitXAuthAck
	stWaitCfgReq
	stWaitCfgRep
	stWaitQM1
	stWaitQM2
	stWaitQM3
	stDone
	stFailed
)

// retransmit bounds an unanswered IKE message on a lossy path; a reliable path
// (loopback or an established ESP SA) never triggers it.
const (
	ikeRetransmitInterval = 2 * time.Second
	ikeMaxRetransmits     = 5
)

// Session drives one IKEv1 exchange for a single peer. It is transport-neutral:
// datagrams go out through cfg.Send and come in via HandleInbound.
type Session struct {
	cfg    Config
	logger *vlog.Logger

	mu    sync.Mutex
	state sessionState

	initCookie [8]byte
	respCookie [8]byte

	prop              ikeProposal
	propNum           uint8
	dh                cryptoutil.DHGroup
	localPub, peerPub []byte
	ni, nr            []byte // initiator, responder phase-1 nonces
	saBodyI           []byte // initiator's SA payload body, for HASH_I/HASH_R
	keys              *phase1
	// psk is the key phase 1 authenticates with: cfg.PSK, or whatever PSKFor
	// returned for the group identity Aggressive Mode carried.
	psk []byte
	// idI and idR are the raw Identification payload bodies exchanged in phase 1.
	// Aggressive Mode hashes them, so both ends keep the bytes they saw rather
	// than re-rendering an identity that might not be byte-identical.
	idI, idR []byte

	// The Transaction exchange (XAuth and Mode-Config). txMsgID/txIV are the CBC
	// chain for the message ID currently in flight; a new message ID reseeds it.
	txMsgID    uint32
	txIV       []byte
	txID       uint16 // Attribute payload identifier, echoed in the answer
	xauthDone  bool
	xauthUser  string
	assigned   *ModeCfgReply
	cfgAttempt int

	// Dead-peer detection (RFC 3706).
	dpdSeq  uint32
	dpdWait chan struct{}

	// NAT traversal.
	peerNATT bool // the peer advertised a NAT-T vendor ID
	floated  bool // IKE (and ESP) have moved to the NAT-T port

	// Quick Mode.
	esp        espProposal
	qmMsgID    uint32
	qmIV       []byte
	qmNi, qmNr []byte
	inSPI      uint32 // our inbound ESP SPI
	outSPI     uint32 // peer's inbound ESP SPI (stamped on our outbound ESP)

	// Retransmission of the last message we sent. lastSentNATT pins it to the
	// port it originally went out on: the responder floats immediately after
	// sending MM4, and a retransmit of MM4 must still use the pre-float port.
	lastSent     []byte
	lastSentNATT bool
	timer        *time.Timer
	retries      int
}

// InitiatorCookie extracts the initiator cookie that opens every ISAKMP header.
// A server demultiplexes inbound IKE by it rather than by source address, since
// the NAT-T float moves a session to a different port mid-exchange.
func InitiatorCookie(msg []byte) ([8]byte, bool) {
	var c [8]byte
	if len(msg) < isakmpHeaderLen {
		return c, false
	}
	copy(c[:], msg[:8])
	return c, true
}

// NewSession builds an IKE session. The initiator must call Start; the responder
// begins on the first inbound message.
func NewSession(cfg Config) *Session {
	logger := cfg.Logger
	return &Session{cfg: cfg, logger: logger, psk: cfg.PSK}
}

// Start begins phase 1 (initiator only).
func (s *Session) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Role != Initiator || s.state != stInit {
		return
	}
	_, _ = rand.Read(s.initCookie[:])
	if s.cfg.Mode == ModeAggressive {
		if err := s.sendAM1(); err != nil {
			s.failLocked(err)
			return
		}
		s.state = stWaitAM2
		return
	}
	if err := s.sendMM1(); err != nil {
		s.failLocked(err)
		return
	}
	s.state = stWaitMM2
}

// HandleInbound processes one inbound IKE datagram. It reports whether the
// message authenticated under the established SA, which is the one thing a
// caller tracking the peer's address needs to know.
//
// Only an established session can say yes. Before phase 2 completes, early
// messages are plaintext and a failed one fails the whole session anyway, so
// there is no settled peer for a forgery to hijack and the caller follows each
// message's source as before. After it, the initiator cookie that routes a
// datagram here is cleartext in every IKE header, so "a message arrived for
// this session" proves nothing about who sent it: an address learned from one
// that did not decrypt and verify is an address anyone on the path chose.
func (s *Session) HandleInbound(pkt []byte) (authenticated bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == stFailed {
		return false
	}
	h, first, rest, err := parseHeader(pkt)
	if err != nil {
		return false
	}
	// An established session still has one live exchange: the Informational one
	// carrying dead-peer detection. Everything else after phase 2 is ignored.
	if s.state == stDone {
		if h.exchange == exchangeInformational && h.flags&flagEncryption != 0 {
			if derr := s.handleDPD(h, first, rest); derr != nil {
				s.logger.Printf("ikev1: DPD: %v", derr)
				return false
			}
			return true
		}
		return false
	}
	if err := s.dispatch(h, first, rest); err != nil {
		s.failLocked(err)
	}
	return false
}

func (s *Session) dispatch(h header, first uint8, rest []byte) error {
	// Route on the exchange type, not just on what the state machine expects
	// next. A peer may interleave an Informational exchange (a notify such as
	// INITIAL_CONTACT, or a delete) at any point; feeding one to the Main Mode
	// handlers would fail the session over a message that was never part of it.
	switch h.exchange {
	case exchangeMain, exchangeAggressive, exchangeTransaction, exchangeQuick:
	default:
		s.logger.Printf("ikev1: ignoring exchange type %d", h.exchange)
		return nil
	}
	if want := s.expectedExchange(); want != 0 && h.exchange != want {
		s.logger.Printf("ikev1: ignoring exchange type %d while awaiting %d", h.exchange, want)
		return nil
	}
	// Notifications ride the same exchange type as Main Mode, so a plaintext
	// message must be screened for them before the handlers see it. Encrypted
	// ones are screened by the handler that decrypts them.
	if h.flags&flagEncryption == 0 {
		if payloads, _, err := parsePayloads(first, rest); err == nil {
			informational, nerr := s.handleNotifies(payloads)
			if nerr != nil {
				return nerr
			}
			if informational {
				return nil
			}
		}
	}
	switch s.cfg.Role {
	case Initiator:
		return s.dispatchInitiator(h, first, rest)
	default:
		return s.dispatchResponder(h, first, rest)
	}
}

// expectedExchange is the exchange type the current state is waiting for, or 0
// if the state accepts either.
func (s *Session) expectedExchange() uint8 {
	switch s.state {
	case stInit:
		if s.cfg.Mode == ModeAggressive {
			return exchangeAggressive
		}
		return exchangeMain
	case stWaitMM2, stWaitMM3, stWaitMM4, stWaitMM5, stWaitMM6:
		return exchangeMain
	case stWaitAM2, stWaitAM3:
		return exchangeAggressive
	case stWaitXAuthReq, stWaitXAuthRep, stWaitXAuthSet, stWaitXAuthAck, stWaitCfgReq, stWaitCfgRep:
		return exchangeTransaction
	case stWaitQM1, stWaitQM2, stWaitQM3:
		return exchangeQuick
	}
	return 0
}

// --- transmit / retransmit ---

func (s *Session) transmit(msg []byte) error {
	s.lastSent = msg
	s.lastSentNATT = s.floated
	s.retries = 0
	s.armTimer()
	return s.cfg.Send(msg, s.floated)
}

func (s *Session) armTimer() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(ikeRetransmitInterval, s.onRetransmit)
}

func (s *Session) onRetransmit() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == stDone || s.state == stFailed || s.lastSent == nil {
		return
	}
	s.retries++
	if s.retries > ikeMaxRetransmits {
		s.failLocked(fmt.Errorf("ikev1: exchange timed out"))
		return
	}
	_ = s.cfg.Send(s.lastSent, s.lastSentNATT)
	s.timer = time.AfterFunc(ikeRetransmitInterval, s.onRetransmit)
}

// advance clears the retransmit state once a message is accepted.
func (s *Session) advance() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.lastSent = nil
}

func (s *Session) failLocked(err error) {
	if s.state == stFailed || s.state == stDone {
		return
	}
	s.state = stFailed
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.cfg.Handler.Failed(err)
}

func (s *Session) mmHeader(exchange, flags uint8, msgID uint32) header {
	return header{initCookie: s.initCookie, respCookie: s.respCookie, exchange: exchange, flags: flags, messageID: msgID}
}

// nonce returns a fresh random nonce.
func nonce() []byte {
	b := make([]byte, nonceLen)
	_, _ = rand.Read(b)
	return b
}

func randSPI() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	v := binary.BigEndian.Uint32(b[:])
	if v == 0 {
		v = 1
	}
	return v
}

// constEq compares two byte slices in constant time.
func constEq(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
