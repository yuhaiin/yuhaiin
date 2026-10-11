package ppp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/xen0bit/veepin/internal/mschap"
)

// Authenticator returns the password for a username, or ok=false if unknown. The
// server session uses it to verify a client's MS-CHAPv2 response.
type Authenticator func(username string) (password string, ok bool)

// ServerHandler receives the server session's lifecycle events. The SSTP layer
// implements it: Authenticated hands back the credentials the crypto binding
// needs, NetworkUp signals the tunnel can carry IP, and Closed reports teardown.
type ServerHandler interface {
	Authenticated(username, password string, ntResponse [mschap.NTResponseLen]byte)
	NetworkUp()
	Closed(err error)
}

// ServerConfig is the addressing a server assigns a client over IPCP.
type ServerConfig struct {
	ClientIP net.IP // address assigned to the client
	ServerIP net.IP // server's own inner address (its IPCP request)
	DNS      []net.IP
	Auth     Authenticator
	// NoAuth runs the link without PPP-level authentication: LCP omits the
	// Auth-Protocol option and the link goes straight to IPCP with no CHAP
	// challenge. It is for carriers that authenticate above PPP -- Fortinet, whose
	// SVPNCOOKIE has already done so. With it unset (the SSTP default) MS-CHAPv2
	// is required and cfg.Auth verifies the client.
	NoAuth bool
}

// ServerSession is the authenticator side of a PPP link: it opens LCP requiring
// MS-CHAPv2, challenges the client and verifies its response, then assigns the
// client an address over IPCP. Like the client Session it assumes a reliable,
// in-order transport and drives purely from received packets.
type ServerSession struct {
	cfg ServerConfig
	tr  Transport
	h   ServerHandler

	mu    sync.Mutex
	phase phase
	magic uint32
	reqID byte

	lcpReqID                    byte
	lcpConfigReq                []byte // the outstanding request, for retransmission
	lcpLocalOpen, lcpRemoteOpen bool
	lcpNoMagic                  bool // set if a NoAuth client rejected Magic-Number

	authChallenge [mschap.ChallengeLen]byte
	username      string
	password      string
	ntResponse    [mschap.NTResponseLen]byte

	ipcpReqID                     byte
	ipcpConfigReq                 []byte // the outstanding request, for retransmission
	ipcpLocalOpen, ipcpRemoteOpen bool

	lcpRestart, ipcpRestart restartTimer
}

// NewServer builds a PPP server session that authenticates clients via cfg.Auth,
// assigns cfg.ClientIP, sends frames through tr, and reports events to h.
func NewServer(cfg ServerConfig, tr Transport, h ServerHandler) *ServerSession {
	var magic [4]byte
	_, _ = rand.Read(magic[:])
	return &ServerSession{
		cfg:   cfg,
		tr:    tr,
		h:     h,
		magic: binary.BigEndian.Uint32(magic[:]),
	}
}

// Start opens the link by sending the server's LCP Configure-Request, which
// demands MS-CHAPv2 authentication.
func (s *ServerSession) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendLCPConfigReq()
}

// Receive dispatches one inbound PPP frame by protocol.
func (s *ServerSession) Receive(frame []byte) {
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

func (s *ServerSession) send(protocol uint16, payload []byte) {
	if err := s.tr.SendPPP(encodeFrame(protocol, payload)); err != nil {
		s.failLocked(fmt.Errorf("ppp: send: %w", err))
	}
}

func (s *ServerSession) nextID() byte {
	s.reqID++
	return s.reqID
}

func (s *ServerSession) failLocked(err error) {
	if s.phase == phaseClosed {
		return
	}
	s.phase = phaseClosed
	s.lcpRestart.stop()
	s.ipcpRestart.stop()
	s.h.Closed(err)
}

// withLock runs fn with the session locked, for the Restart timer's callback.
func (s *ServerSession) withLock(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == phaseClosed {
		return
	}
	fn()
}

// --- LCP ---

func (s *ServerSession) sendLCPConfigReq() {
	var magic [4]byte
	binary.BigEndian.PutUint32(magic[:], s.magic)
	var opts []option
	if !s.cfg.NoAuth {
		// The authenticator is the side that requests an Auth-Protocol; omitting it
		// is how the peer is told this link does no PPP-level authentication.
		opts = append(opts, option{Type: optAuthProto, Value: authMSCHAPv2})
	}
	if !s.lcpNoMagic {
		opts = append(opts, option{Type: optMagic, Value: magic[:]})
	}
	s.lcpReqID = s.nextID()
	s.lcpConfigReq = cpPacket{Code: codeConfigureRequest, ID: s.lcpReqID, Body: marshalOptions(opts)}.marshal()
	s.resendLCPConfigReq()
}

// resendLCPConfigReq (re)transmits the outstanding LCP Configure-Request and
// re-arms the Restart timer, reusing the original identifier.
func (s *ServerSession) resendLCPConfigReq() {
	s.send(ProtocolLCP, s.lcpConfigReq)
	s.lcpRestart.arm(s.withLock, s.resendLCPConfigReq, func() {
		s.failLocked(fmt.Errorf("ppp: no reply to the LCP Configure-Request"))
	})
}

func (s *ServerSession) handleLCP(payload []byte) {
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
	case codeConfigureNak, codeConfigureReject:
		if s.cfg.NoAuth {
			// The only option we sent is Magic-Number; a client that will not accept
			// it can run without it, so drop it and re-request rather than fail.
			s.lcpNoMagic = true
			s.sendLCPConfigReq()
			return
		}
		// The client rejected or naked our request (auth-proto or magic). We require
		// MS-CHAPv2, so a client that will not accept it cannot proceed.
		s.failLocked(fmt.Errorf("ppp: client rejected MS-CHAPv2 authentication"))
	case codeTerminateRequest:
		s.send(ProtocolLCP, cpPacket{Code: codeTerminateAck, ID: pkt.ID}.marshal())
		s.failLocked(fmt.Errorf("ppp: client closed the link"))
	case codeEchoRequest:
		s.sendEchoReply(pkt)
	}
}

func (s *ServerSession) handleLCPConfigReq(pkt cpPacket) {
	opts, ok := parseOptions(pkt.Body)
	if !ok {
		return
	}
	var rejected []option
	for _, o := range opts {
		switch o.Type {
		case optMRU, optMagic, optQuality, optPFC, optACFC:
			// Acceptable: we send full frames regardless.
		default:
			rejected = append(rejected, o)
		}
	}
	if len(rejected) > 0 {
		s.send(ProtocolLCP, cpPacket{Code: codeConfigureReject, ID: pkt.ID, Body: marshalOptions(rejected)}.marshal())
		return
	}
	s.send(ProtocolLCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}.marshal())
	s.lcpRemoteOpen = true
	s.maybeLCPUp()
}

func (s *ServerSession) sendEchoReply(req cpPacket) {
	var magic [4]byte
	binary.BigEndian.PutUint32(magic[:], s.magic)
	body := magic[:]
	if len(req.Body) >= 4 {
		body = append(magic[:], req.Body[4:]...)
	}
	s.send(ProtocolLCP, cpPacket{Code: codeEchoReply, ID: req.ID, Body: body}.marshal())
}

func (s *ServerSession) maybeLCPUp() {
	if s.phase != phaseLCP || !s.lcpLocalOpen || !s.lcpRemoteOpen {
		return
	}
	if s.cfg.NoAuth {
		// No PPP authentication: the carrier authenticated already, so assign the
		// address straight away.
		s.phase = phaseIPCP
		s.sendIPCPConfigReq()
		return
	}
	s.phase = phaseAuth
	s.sendChallenge()
}

// --- MS-CHAPv2 authentication (authenticator role) ---

func (s *ServerSession) sendChallenge() {
	if _, err := rand.Read(s.authChallenge[:]); err != nil {
		s.failLocked(fmt.Errorf("ppp: challenge: %w", err))
		return
	}
	s.send(ProtocolCHAP, cpPacket{Code: chapChallenge, ID: s.nextID(), Body: buildChallenge(s.authChallenge, "veepin")}.marshal())
}

func (s *ServerSession) handleCHAP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok || pkt.Code != chapResponse {
		return
	}
	peerCh, ntResp, username, ok := parseResponse(pkt.Body)
	if !ok {
		s.failLocked(fmt.Errorf("ppp: malformed MS-CHAPv2 response"))
		return
	}
	password, known := s.cfg.Auth(username)
	if !known || !verifyResponse(s.authChallenge, peerCh, username, password, ntResp) {
		s.send(ProtocolCHAP, cpPacket{Code: chapFailure, ID: pkt.ID, Body: buildFailure()}.marshal())
		s.failLocked(fmt.Errorf("ppp: authentication failed for %q", username))
		return
	}

	s.username, s.password, s.ntResponse = username, password, ntResp
	success := buildSuccess(s.authChallenge, peerCh, username, password, ntResp)
	s.send(ProtocolCHAP, cpPacket{Code: chapSuccess, ID: pkt.ID, Body: success}.marshal())

	s.h.Authenticated(username, password, ntResp)
	s.phase = phaseIPCP
	s.sendIPCPConfigReq()
}

// --- IPCP ---

func (s *ServerSession) sendIPCPConfigReq() {
	opts := []option{{Type: optIPAddress, Value: s.cfg.ServerIP.To4()}}
	s.ipcpReqID = s.nextID()
	s.ipcpConfigReq = cpPacket{Code: codeConfigureRequest, ID: s.ipcpReqID, Body: marshalOptions(opts)}.marshal()
	s.resendIPCPConfigReq()
}

// resendIPCPConfigReq (re)transmits the outstanding IPCP Configure-Request and
// re-arms the Restart timer, reusing the original identifier.
func (s *ServerSession) resendIPCPConfigReq() {
	s.send(ProtocolIPCP, s.ipcpConfigReq)
	s.ipcpRestart.arm(s.withLock, s.resendIPCPConfigReq, func() {
		s.failLocked(fmt.Errorf("ppp: no reply to the IPCP Configure-Request"))
	})
}

func (s *ServerSession) handleIPCP(payload []byte) {
	pkt, ok := parseCP(payload)
	if !ok {
		return
	}
	s.ipcpRestart.alive()
	switch pkt.Code {
	case codeConfigureRequest:
		s.handleIPCPConfigReq(pkt)
	case codeConfigureAck:
		if pkt.ID == s.ipcpReqID {
			s.ipcpRestart.stop()
			s.ipcpLocalOpen = true
			s.maybeIPCPUp()
		}
	case codeConfigureNak, codeConfigureReject:
		// The client naked our server address; drop the disputed option and resend a
		// bare request, which every client accepts.
		s.sendIPCPConfigReq()
	}
}

// handleIPCPConfigReq answers the client's address request: it Naks any option
// whose value is not what the server assigns (the client's address and DNS),
// steering the client to the assigned values; once they match it Acks.
func (s *ServerSession) handleIPCPConfigReq(pkt cpPacket) {
	opts, ok := parseOptions(pkt.Body)
	if !ok {
		return
	}
	var nak []option
	for _, o := range opts {
		switch o.Type {
		case optIPAddress:
			if !ipEq(o.Value, s.cfg.ClientIP) {
				nak = append(nak, option{Type: optIPAddress, Value: s.cfg.ClientIP.To4()})
			}
		case optPrimaryDNS:
			if want := s.dnsAt(0); want != nil && !ipEq(o.Value, want) {
				nak = append(nak, option{Type: optPrimaryDNS, Value: want.To4()})
			}
		case optSecondaryDNS:
			if want := s.dnsAt(1); want != nil && !ipEq(o.Value, want) {
				nak = append(nak, option{Type: optSecondaryDNS, Value: want.To4()})
			}
		}
	}
	if len(nak) > 0 {
		s.send(ProtocolIPCP, cpPacket{Code: codeConfigureNak, ID: pkt.ID, Body: marshalOptions(nak)}.marshal())
		return
	}
	s.send(ProtocolIPCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}.marshal())
	s.ipcpRemoteOpen = true
	s.maybeIPCPUp()
}

func (s *ServerSession) dnsAt(i int) net.IP {
	if i < len(s.cfg.DNS) {
		return s.cfg.DNS[i]
	}
	return nil
}

func (s *ServerSession) maybeIPCPUp() {
	if s.phase != phaseIPCP || !s.ipcpLocalOpen || !s.ipcpRemoteOpen {
		return
	}
	s.phase = phaseUp
	s.h.NetworkUp()
}

// ipEq reports whether a 4-byte option value equals an IP address.
func ipEq(value []byte, ip net.IP) bool {
	v4 := ip.To4()
	return len(value) == 4 && v4 != nil && value[0] == v4[0] && value[1] == v4[1] && value[2] == v4[2] && value[3] == v4[3]
}
