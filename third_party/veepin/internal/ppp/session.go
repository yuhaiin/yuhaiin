package ppp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/mschap"
)

// ErrAuth reports an MS-CHAPv2 exchange the peer refused: a CHAP Failure, or a
// Success whose authenticator does not verify. Both are the same fact to a
// caller -- the credentials are wrong -- and both must be distinguishable from
// a transport fault, because `veepin connect -retry` treats a credential
// failure as permanent and everything else as an outage worth waiting out.
//
// A mismatched authenticator is on this side of the line deliberately. It means
// the peer proved it does not know the password, which is a failed
// authentication and not a malformed packet, even though what arrived was
// well-formed.
var ErrAuth = errors.New("ppp: authentication failed")

// LCP option types (RFC 1661 section 6).
const (
	optMRU       = 1
	optAuthProto = 3
	optQuality   = 4
	optMagic     = 5
	optPFC       = 7
	optACFC      = 8
)

// IPCP option types (RFC 1332).
const (
	optIPAddress    = 3
	optPrimaryDNS   = 0x81
	optSecondaryDNS = 0x83
)

// authMSCHAPv2 is the LCP Auth-Protocol option value for MS-CHAPv2: the CHAP
// protocol number followed by the MS-CHAPv2 algorithm identifier.
var authMSCHAPv2 = []byte{0xc2, 0x23, 0x81}

// DefaultMRU is the maximum receive unit this package advertises, comfortably
// inside a TLS record over a typical path.
const DefaultMRU = 1400

// defaultMRU is the unexported spelling the session code uses.
const defaultMRU = DefaultMRU

// IPConfig is the network configuration IPCP assigns the client. PeerIP is the
// server's own inner address (from its IPCP Configure-Request); the tunnel uses
// it as the point-to-point gateway.
type IPConfig struct {
	LocalIP net.IP
	PeerIP  net.IP
	DNS     []net.IP
}

// Handler receives the PPP session's lifecycle events. The SSTP layer implements
// it: on Authenticated it computes the crypto binding and sends Call Connected,
// and on NetworkUp the tunnel is ready to carry IP.
type Handler interface {
	Authenticated(ntResponse [mschap.NTResponseLen]byte)
	NetworkUp(cfg IPConfig)
	Closed(err error)
}

// Transport sends a fully-framed PPP packet; the SSTP layer wraps it in a data
// packet on the TLS connection.
type Transport interface {
	SendPPP(frame []byte) error
}

type phase int

const (
	phaseLCP phase = iota
	phaseAuth
	phaseIPCP
	phaseUp
	phaseClosed
)

// Session is a PPP client link: it negotiates LCP, authenticates with
// MS-CHAPv2, and negotiates IPCP, then carries IP. It is driven by received
// packets, with one timer: the RFC 1661 Restart timer covering an outstanding
// Configure-Request, which only fires on a lossy carrier such as L2TP's
// unreliable data channel (see restart.go).
type Session struct {
	username, password string
	tr                 Transport
	h                  Handler

	mu    sync.Mutex
	phase phase
	magic uint32
	reqID byte

	lcpRestart, ipcpRestart restartTimer

	lcpReqID                    byte
	lcpConfigReq                []byte // the outstanding request, for retransmission
	lcpLocalOpen, lcpRemoteOpen bool
	lcpAuthNaks                 int
	lcpUseMRU, lcpUseMagic      bool
	lcpMRU                      uint16
	// peerRequiresAuth records whether the server's accepted LCP Configure-Request
	// carried an Auth-Protocol option. When it did not — as with Fortinet, whose
	// HTTPS layer already authenticated — there is no CHAP exchange and the link
	// goes straight from LCP to IPCP. SSTP servers always request auth, so this is
	// true there and the MS-CHAPv2 path is unchanged.
	peerRequiresAuth bool

	ipcpReqID                     byte
	ipcpConfigReq                 []byte // the outstanding request, for retransmission
	ipcpLocalOpen, ipcpRemoteOpen bool
	reqIP, reqDNS1, reqDNS2       net.IP
	peerIP                        net.IP

	authChallenge, peerChallenge [mschap.ChallengeLen]byte
	ntResponse                   [mschap.NTResponseLen]byte

	// echoID is the identifier of the LCP Echo-Request a probe is waiting on,
	// and echoWait the channel closed when the matching Echo-Reply arrives (or
	// the link dies). LCP matches a reply to its request by identifier, so that
	// is what this keys on rather than the magic number, which says whose link
	// it is and not which question it answers.
	echoID   byte
	echoWait chan struct{}
}

// New builds a PPP client session that authenticates as username/password,
// sends frames through tr, and reports events to h.
func New(username, password string, tr Transport, h Handler) *Session {
	var magic [4]byte
	_, _ = rand.Read(magic[:])
	return &Session{
		username:    username,
		password:    password,
		tr:          tr,
		h:           h,
		magic:       binary.BigEndian.Uint32(magic[:]),
		lcpUseMRU:   true,
		lcpUseMagic: true,
		lcpMRU:      defaultMRU,
	}
}

// Start opens the link by sending the initial LCP Configure-Request.
func (s *Session) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendLCPConfigReq()
}

// Receive dispatches one inbound PPP frame by protocol. The SSTP layer calls it
// for every data-packet payload during negotiation, and for control frames once
// the tunnel is up.
func (s *Session) Receive(frame []byte) {
	protocol, payload, ok := decodeFrame(frame)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == phaseClosed {
		return
	}
	switch protocol {
	case ProtocolLCP:
		s.handleLCP(payload)
	case ProtocolCHAP:
		s.handleCHAP(payload)
	case ProtocolIPCP:
		s.handleIPCP(payload)
	}
}

// IsIP reports whether a received PPP frame carries an IP packet, and returns
// it. The SSTP tunnel uses this to split inbound data between the TUN and the
// PPP control machinery once the link is up.
//
// The packet is trimmed to the length its own header declares, which discards
// any padding the peer added. RFC 1661 §5.1 allows a sender to pad the
// Information field up to the MRU and makes distinguishing padding from data
// the carried protocol's business — IP does that with its Total Length — so a
// conforming PPP receiver has to trim here whether or not it ever pads itself.
func IsIP(frame []byte) ([]byte, bool) {
	protocol, payload, ok := decodeFrame(frame)
	if !ok || protocol != ProtocolIP {
		return nil, false
	}
	trimmed := dataplane.TrimToIP(payload)
	if trimmed == nil {
		return nil, false // not a well-formed IP packet
	}
	return trimmed, true
}

// EncapsulateIP frames an outbound IP packet as a PPP frame for a data packet.
func EncapsulateIP(ipPacket []byte) []byte {
	return encodeFrame(ProtocolIP, ipPacket)
}

// EncapsulateIPPadded is EncapsulateIP with the Information field padded out to
// at least minInner octets, so the frame's size on the wire — and with it the
// TLS record a stream-carried protocol writes it into — says less about the
// packet inside. dataplane.Shaper decides when and how far.
//
// This is RFC 1661 §5.1 padding, so it needs no negotiation and no peer
// support: the padding octets are past the end of the IP packet's own declared
// length, and every conforming receiver delimits by that.
func EncapsulateIPPadded(ipPacket []byte, minInner int) []byte {
	if minInner <= len(ipPacket) {
		return encodeFrame(ProtocolIP, ipPacket)
	}
	// One allocation: build the padded Information field directly inside the
	// frame rather than padding a copy and then framing it.
	out := make([]byte, frameHeaderLen+minInner)
	putFrameHeader(out, ProtocolIP)
	copy(out[frameHeaderLen:], ipPacket)
	// The tail stays zero from make — that is the padding.
	return out
}

func (s *Session) send(protocol uint16, payload []byte) {
	if err := s.tr.SendPPP(encodeFrame(protocol, payload)); err != nil {
		s.failLocked(fmt.Errorf("ppp: send: %w", err))
	}
}

func (s *Session) nextID() byte {
	s.reqID++
	return s.reqID
}

func (s *Session) failLocked(err error) {
	if s.phase == phaseClosed {
		return
	}
	s.phase = phaseClosed
	s.lcpRestart.stop()
	s.ipcpRestart.stop()
	// Release a probe blocked on a reply that is never coming, so a link that
	// has already declared itself dead does not also cost the caller a timeout.
	if s.echoWait != nil {
		close(s.echoWait)
		s.echoWait = nil
	}
	s.h.Closed(err)
}

// --- LCP ---

func (s *Session) sendLCPConfigReq() {
	var opts []option
	if s.lcpUseMRU {
		var mru [2]byte
		binary.BigEndian.PutUint16(mru[:], s.lcpMRU)
		opts = append(opts, option{Type: optMRU, Value: mru[:]})
	}
	if s.lcpUseMagic {
		var magic [4]byte
		binary.BigEndian.PutUint32(magic[:], s.magic)
		opts = append(opts, option{Type: optMagic, Value: magic[:]})
	}
	s.lcpReqID = s.nextID()
	s.lcpConfigReq = cpPacket{Code: codeConfigureRequest, ID: s.lcpReqID, Body: marshalOptions(opts)}.marshal()
	s.resendLCPConfigReq()
}

// resendLCPConfigReq (re)transmits the outstanding LCP Configure-Request and
// re-arms the Restart timer, reusing the original identifier.
func (s *Session) resendLCPConfigReq() {
	s.send(ProtocolLCP, s.lcpConfigReq)
	s.lcpRestart.arm(s.withLock, s.resendLCPConfigReq, func() {
		s.failLocked(fmt.Errorf("ppp: no reply to the LCP Configure-Request"))
	})
}

// withLock runs fn with the session locked, for the Restart timer's callback.
func (s *Session) withLock(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == phaseClosed {
		return
	}
	fn()
}

// applyLCPNak adopts the values the peer suggested for our request (e.g. a
// smaller MRU) so the next request converges.
func (s *Session) applyLCPNak(body []byte) {
	opts, ok := parseOptions(body)
	if !ok {
		return
	}
	for _, o := range opts {
		switch o.Type {
		case optMRU:
			if len(o.Value) == 2 {
				s.lcpMRU = binary.BigEndian.Uint16(o.Value)
			}
		case optMagic:
			if len(o.Value) == 4 {
				s.magic = binary.BigEndian.Uint32(o.Value)
			}
		}
	}
}

// applyLCPReject drops options the peer refused to understand (SoftEther rejects
// Magic-Number, for one) so the next request omits them.
func (s *Session) applyLCPReject(body []byte) {
	opts, ok := parseOptions(body)
	if !ok {
		return
	}
	for _, o := range opts {
		switch o.Type {
		case optMRU:
			s.lcpUseMRU = false
		case optMagic:
			s.lcpUseMagic = false
		}
	}
}

func (s *Session) handleLCP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok {
		return
	}
	// Any LCP reply proves the peer is alive, so the Restart budget for the next
	// request starts fresh.
	s.lcpRestart.alive()
	switch pkt.Code {
	case codeConfigureRequest:
		s.handleLCPConfigReq(pkt)
	case codeConfigureAck:
		if pkt.ID == s.lcpReqID {
			s.lcpRestart.stop()
			s.lcpLocalOpen = true
			s.maybeLCPUp()
		}
	case codeConfigureNak:
		if pkt.ID == s.lcpReqID {
			s.applyLCPNak(pkt.Body)
			s.sendLCPConfigReq()
		}
	case codeConfigureReject:
		if pkt.ID == s.lcpReqID {
			s.applyLCPReject(pkt.Body)
			s.sendLCPConfigReq()
		}
	case codeTerminateRequest:
		s.send(ProtocolLCP, cpPacket{Code: codeTerminateAck, ID: pkt.ID}.marshal())
		s.failLocked(fmt.Errorf("ppp: peer closed the link"))
	case codeEchoRequest:
		s.sendEchoReply(pkt)
	case codeEchoReply:
		if s.echoWait != nil && pkt.ID == s.echoID {
			close(s.echoWait)
			s.echoWait = nil
		}
	}
}

// maxAuthNaks bounds how many times we will Configure-Nak the peer's auth
// protocol before giving up, so a server that only ever offers something we
// cannot do (e.g. PAP) fails cleanly instead of looping forever.
const maxAuthNaks = 5

func (s *Session) handleLCPConfigReq(pkt cpPacket) {
	opts, ok := parseOptions(pkt.Body)
	if !ok {
		return
	}
	var rejected, naked []option
	for _, o := range opts {
		switch o.Type {
		case optMRU, optMagic, optQuality, optPFC, optACFC:
			// Acceptable: we send full frames regardless, so compression options
			// only permit, never require, and cost us nothing to accept.
		case optAuthProto:
			if string(o.Value) != string(authMSCHAPv2) {
				// We only implement MS-CHAPv2. The option is understood but its value
				// is unacceptable, so Nak it proposing MS-CHAPv2 rather than Reject —
				// servers such as SoftEther offer PAP first and re-offer MS-CHAPv2
				// when Nak'd.
				naked = append(naked, option{Type: optAuthProto, Value: authMSCHAPv2})
			}
		default:
			rejected = append(rejected, o)
		}
	}
	switch {
	case len(rejected) > 0:
		// Reject takes priority over Nak (RFC 1661 6): drop options we do not
		// recognise; the peer re-requests without them and we then settle auth.
		s.send(ProtocolLCP, cpPacket{Code: codeConfigureReject, ID: pkt.ID, Body: marshalOptions(rejected)}.marshal())
	case len(naked) > 0:
		s.lcpAuthNaks++
		if s.lcpAuthNaks > maxAuthNaks {
			s.failLocked(fmt.Errorf("ppp: server offers no auth protocol we support (need MS-CHAPv2)"))
			return
		}
		s.send(ProtocolLCP, cpPacket{Code: codeConfigureNak, ID: pkt.ID, Body: marshalOptions(naked)}.marshal())
	default:
		// This request is acceptable as-is. Whether it asked for authentication
		// decides what happens after LCP: an Auth-Protocol option present here means
		// a CHAP challenge is coming, its absence means the link authenticates
		// elsewhere (Fortinet) and proceeds straight to IPCP.
		s.peerRequiresAuth = hasAuthProto(opts)
		s.send(ProtocolLCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}.marshal())
		s.lcpRemoteOpen = true
		s.maybeLCPUp()
	}
}

// hasAuthProto reports whether an option list requests link authentication.
func hasAuthProto(opts []option) bool {
	for _, o := range opts {
		if o.Type == optAuthProto {
			return true
		}
	}
	return false
}

// ErrLinkClosed reports an echo on a link that is no longer up.
var ErrLinkClosed = errors.New("ppp: link is closed")

// SendEcho sends an LCP Echo-Request and waits for the peer's Echo-Reply.
//
// This is PPP's own liveness check (RFC 1661 section 5.8) and it is the right
// probe for any carrier that can go quiet without erroring: it travels the same
// path the data does, so it tests that path rather than a control connection
// sitting beside it.
//
// This end has always answered a peer's Echo-Request and never sent one. Half a
// mechanism proves this end alive to the peer and learns nothing about the
// peer, which is the wrong half to have on a client.
func (s *Session) SendEcho(ctx context.Context) error {
	s.mu.Lock()
	if s.phase == phaseClosed {
		s.mu.Unlock()
		return ErrLinkClosed
	}
	wait := s.echoWait
	if wait == nil {
		wait = make(chan struct{})
		s.echoWait, s.echoID = wait, s.nextID()
		var magic [4]byte
		binary.BigEndian.PutUint32(magic[:], s.magic)
		s.send(ProtocolLCP, cpPacket{Code: codeEchoRequest, ID: s.echoID, Body: magic[:]}.marshal())
	}
	s.mu.Unlock()

	select {
	case <-wait:
		s.mu.Lock()
		closed := s.phase == phaseClosed
		s.mu.Unlock()
		if closed {
			return ErrLinkClosed
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) sendEchoReply(req cpPacket) {
	var magic [4]byte
	binary.BigEndian.PutUint32(magic[:], s.magic)
	// Echo-Reply body is our magic number followed by the request's data.
	body := magic[:]
	if len(req.Body) >= 4 {
		body = append(magic[:], req.Body[4:]...)
	}
	s.send(ProtocolLCP, cpPacket{Code: codeEchoReply, ID: req.ID, Body: body}.marshal())
}

func (s *Session) maybeLCPUp() {
	if s.phase != phaseLCP || !s.lcpLocalOpen || !s.lcpRemoteOpen {
		return
	}
	if s.peerRequiresAuth {
		s.phase = phaseAuth // wait for the server's MS-CHAPv2 challenge
		return
	}
	// No authentication was negotiated: skip straight to IPCP.
	s.phase = phaseIPCP
	s.startIPCP()
}

// --- MS-CHAPv2 authentication ---

func (s *Session) handleCHAP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok {
		return
	}
	switch pkt.Code {
	case chapChallenge:
		ac, _, ok := parseChallenge(pkt.Body)
		if !ok {
			s.failLocked(fmt.Errorf("ppp: malformed MS-CHAPv2 challenge"))
			return
		}
		s.authChallenge = ac
		body, pc, nt, err := buildResponse(ac, s.username, s.password)
		if err != nil {
			s.failLocked(err)
			return
		}
		s.peerChallenge, s.ntResponse = pc, nt
		s.send(ProtocolCHAP, cpPacket{Code: chapResponse, ID: pkt.ID, Body: body}.marshal())
	case chapSuccess:
		if err := verifySuccess(pkt.Body, s.authChallenge, s.peerChallenge, s.username, s.password, s.ntResponse); err != nil {
			s.failLocked(err)
			return
		}
		s.h.Authenticated(s.ntResponse)
		s.phase = phaseIPCP
		s.startIPCP()
	case chapFailure:
		s.failLocked(fmt.Errorf("%w: %s", ErrAuth, failureMessage(pkt.Body)))
	}
}

// --- IPCP ---

func (s *Session) startIPCP() {
	s.reqIP = net.IPv4zero.To4()
	s.reqDNS1 = net.IPv4zero.To4()
	s.reqDNS2 = net.IPv4zero.To4()
	s.sendIPCPConfigReq()
}

func (s *Session) sendIPCPConfigReq() {
	opts := []option{{Type: optIPAddress, Value: s.reqIP}}
	if s.reqDNS1 != nil {
		opts = append(opts, option{Type: optPrimaryDNS, Value: s.reqDNS1})
	}
	if s.reqDNS2 != nil {
		opts = append(opts, option{Type: optSecondaryDNS, Value: s.reqDNS2})
	}
	s.ipcpReqID = s.nextID()
	s.ipcpConfigReq = cpPacket{Code: codeConfigureRequest, ID: s.ipcpReqID, Body: marshalOptions(opts)}.marshal()
	s.resendIPCPConfigReq()
}

// resendIPCPConfigReq (re)transmits the outstanding IPCP Configure-Request and
// re-arms the Restart timer, reusing the original identifier.
func (s *Session) resendIPCPConfigReq() {
	s.send(ProtocolIPCP, s.ipcpConfigReq)
	s.ipcpRestart.arm(s.withLock, s.resendIPCPConfigReq, func() {
		s.failLocked(fmt.Errorf("ppp: no reply to the IPCP Configure-Request"))
	})
}

func (s *Session) handleIPCP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok {
		return
	}
	s.ipcpRestart.alive()
	switch pkt.Code {
	case codeConfigureRequest:
		// Accept the server's own IPCP options and record its inner address, which
		// the tunnel uses as the point-to-point gateway.
		if opts, ok := parseOptions(pkt.Body); ok {
			for _, o := range opts {
				if o.Type == optIPAddress && len(o.Value) == 4 {
					s.peerIP = net.IP(append([]byte(nil), o.Value...))
				}
			}
		}
		s.send(ProtocolIPCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}.marshal())
		s.ipcpRemoteOpen = true
		s.maybeIPCPUp()
	case codeConfigureAck:
		if pkt.ID == s.ipcpReqID {
			s.ipcpRestart.stop()
			s.ipcpLocalOpen = true
			s.maybeIPCPUp()
		}
	case codeConfigureNak:
		s.adoptIPCPValues(pkt.Body)
		s.sendIPCPConfigReq()
	case codeConfigureReject:
		s.dropRejectedIPCP(pkt.Body)
		s.sendIPCPConfigReq()
	}
}

// adoptIPCPValues takes the addresses the server suggested in a Configure-Nak
// and resubmits them, which is how the client learns its assigned IP and DNS.
func (s *Session) adoptIPCPValues(body []byte) {
	opts, ok := parseOptions(body)
	if !ok {
		return
	}
	for _, o := range opts {
		if len(o.Value) != 4 {
			continue
		}
		v := net.IP(append([]byte(nil), o.Value...))
		switch o.Type {
		case optIPAddress:
			s.reqIP = v
		case optPrimaryDNS:
			s.reqDNS1 = v
		case optSecondaryDNS:
			s.reqDNS2 = v
		}
	}
}

// dropRejectedIPCP removes options the server rejected (commonly the DNS
// requests) so the resent request can converge.
func (s *Session) dropRejectedIPCP(body []byte) {
	opts, ok := parseOptions(body)
	if !ok {
		return
	}
	for _, o := range opts {
		switch o.Type {
		case optPrimaryDNS:
			s.reqDNS1 = nil
		case optSecondaryDNS:
			s.reqDNS2 = nil
		}
	}
}

func (s *Session) maybeIPCPUp() {
	if s.phase != phaseIPCP || !s.ipcpLocalOpen || !s.ipcpRemoteOpen {
		return
	}
	s.phase = phaseUp
	cfg := IPConfig{LocalIP: s.reqIP, PeerIP: s.peerIP}
	for _, d := range []net.IP{s.reqDNS1, s.reqDNS2} {
		if d != nil && !d.Equal(net.IPv4zero) {
			cfg.DNS = append(cfg.DNS, d)
		}
	}
	s.h.NetworkUp(cfg)
}
