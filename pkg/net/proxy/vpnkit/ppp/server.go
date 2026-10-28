package ppp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/mschap"
)

// ServerHandler receives events after the server has authenticated the peer.
type ServerHandler interface {
	ServerAuthenticated(username, password string, ntResponse [mschap.NTResponseLen]byte)
	ServerNetworkUp()
}

// ServerSession implements the authenticator side of LCP, MS-CHAPv2 and IPCP.
// Receive and Start must be called from the same goroutine.
type ServerSession struct {
	transport               Transport
	handler                 ServerHandler
	lookup                  func(string) (string, bool)
	localIP, clientIP, dns  net.IP
	phase                   phase
	next                    byte
	lcpRequest, ipcpRequest []byte
	lcpID, ipcpID, chapID   byte
	lcpLocal, lcpRemote     bool
	ipcpLocal, ipcpRemote   bool
	challenge               [mschap.ChallengeLen]byte
	ready                   bool
	naks                    int
}

func NewServer(localIP, clientIP, dns net.IP, lookup func(string) (string, bool), tr Transport, handler ServerHandler) (*ServerSession, error) {
	if localIP.To4() == nil || clientIP.To4() == nil || localIP.Equal(clientIP) || lookup == nil || tr == nil || handler == nil {
		return nil, errors.New("ppp: invalid server configuration")
	}
	if dns != nil && dns.To4() == nil {
		return nil, errors.New("ppp: DNS must be IPv4")
	}
	return &ServerSession{
		transport: tr, handler: handler, lookup: lookup,
		localIP:  append(net.IP(nil), localIP.To4()...),
		clientIP: append(net.IP(nil), clientIP.To4()...),
		dns:      append(net.IP(nil), dns.To4()...),
	}, nil
}

func (s *ServerSession) Up() bool { return s.ready }

func (s *ServerSession) nextID() byte {
	s.next++
	return s.next
}

func (s *ServerSession) send(protocol uint16, packet cpPacket) error {
	return s.transport.SendPPP(encodeFrame(protocol, packet.marshal()))
}

func (s *ServerSession) Start() error {
	s.lcpID = s.nextID()
	var magic [4]byte
	if _, err := rand.Read(magic[:]); err != nil {
		return err
	}
	opts := []option{
		{Type: optMRU, Value: []byte{0x05, 0x78}},
		{Type: optAuthProto, Value: authMSCHAPv2},
		{Type: optMagic, Value: magic[:]},
	}
	s.lcpRequest = marshalOptions(opts)
	return s.send(ProtocolLCP, cpPacket{Code: codeConfigureRequest, ID: s.lcpID, Body: s.lcpRequest})
}

func (s *ServerSession) Receive(frame []byte) error {
	protocol, data, ok := decodeFrame(frame)
	if !ok {
		return errors.New("ppp: invalid frame")
	}
	pkt, ok := parseCP(data)
	if !ok {
		return errors.New("ppp: invalid control packet")
	}
	switch protocol {
	case ProtocolLCP:
		return s.lcp(pkt)
	case ProtocolCHAP:
		if s.phase != phaseAuth {
			return errors.New("ppp: unexpected CHAP packet")
		}
		return s.chap(pkt)
	case ProtocolIPCP:
		if s.phase != phaseIPCP && s.phase != phaseUp {
			return errors.New("ppp: premature IPCP")
		}
		return s.ipcp(pkt)
	default:
		return errors.New("ppp: unsupported protocol")
	}
}

func (s *ServerSession) lcp(pkt cpPacket) error {
	if pkt.Code == codeTerminateRequest {
		_ = s.send(ProtocolLCP, cpPacket{Code: codeTerminateAck, ID: pkt.ID})
		return errors.New("ppp: peer terminated link")
	}
	if pkt.Code == codeEchoRequest {
		return s.send(ProtocolLCP, cpPacket{Code: codeEchoReply, ID: pkt.ID, Body: pkt.Body})
	}
	if s.phase != phaseLCP {
		return nil
	}
	switch pkt.Code {
	case codeConfigureRequest:
		opts, ok := parseOptions(pkt.Body)
		if !ok {
			return errors.New("ppp: malformed LCP options")
		}
		var rejected []option
		for _, opt := range opts {
			switch opt.Type {
			case optMRU, optMagic, optPFC, optACFC:
			default:
				rejected = append(rejected, opt)
			}
		}
		if len(rejected) != 0 {
			return s.send(ProtocolLCP, cpPacket{Code: codeConfigureReject, ID: pkt.ID, Body: marshalOptions(rejected)})
		}
		if err := s.send(ProtocolLCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}); err != nil {
			return err
		}
		s.lcpRemote = true
	case codeConfigureAck:
		if pkt.ID != s.lcpID || !bytes.Equal(pkt.Body, s.lcpRequest) {
			return errors.New("ppp: unexpected LCP ack")
		}
		s.lcpLocal = true
	case codeConfigureNak, codeConfigureReject:
		return errors.New("ppp: peer rejected required LCP settings")
	}
	if s.lcpLocal && s.lcpRemote {
		s.phase = phaseAuth
		s.chapID = s.nextID()
		if _, err := rand.Read(s.challenge[:]); err != nil {
			return err
		}
		body := append([]byte{mschap.ChallengeLen}, s.challenge[:]...)
		body = append(body, "yuhaiin"...)
		return s.send(ProtocolCHAP, cpPacket{Code: chapChallenge, ID: s.chapID, Body: body})
	}
	return nil
}

func (s *ServerSession) chap(pkt cpPacket) error {
	if pkt.Code != chapResponse || pkt.ID != s.chapID {
		return errors.New("ppp: unexpected CHAP response")
	}
	if len(pkt.Body) < 1+mschapResponseValueLen || int(pkt.Body[0]) != mschapResponseValueLen {
		return errors.New("ppp: malformed MS-CHAPv2 response")
	}
	value := pkt.Body[1 : 1+mschapResponseValueLen]
	username := string(pkt.Body[1+mschapResponseValueLen:])
	if username == "" || len(username) > 256 {
		return errors.New("ppp: invalid username")
	}
	password, ok := s.lookup(username)
	var peerChallenge [mschap.ChallengeLen]byte
	copy(peerChallenge[:], value[:16])
	var response [mschap.NTResponseLen]byte
	copy(response[:], value[24:48])
	expected := mschap.GenerateNTResponse(s.challenge, peerChallenge, username, password)
	if !ok || subtle.ConstantTimeCompare(expected[:], response[:]) != 1 {
		_ = s.send(ProtocolCHAP, cpPacket{Code: chapFailure, ID: pkt.ID, Body: []byte("E=691 R=0 M=Authentication failed")})
		return ErrAuth
	}
	success := mschap.AuthenticatorResponse(s.challenge, peerChallenge, username, password, response)
	if err := s.send(ProtocolCHAP, cpPacket{Code: chapSuccess, ID: pkt.ID, Body: []byte(success)}); err != nil {
		return err
	}
	s.handler.ServerAuthenticated(username, password, response)
	s.phase = phaseIPCP
	s.ipcpID = s.nextID()
	s.ipcpRequest = marshalOptions([]option{{Type: optIPAddress, Value: s.localIP}})
	return s.send(ProtocolIPCP, cpPacket{Code: codeConfigureRequest, ID: s.ipcpID, Body: s.ipcpRequest})
}

func (s *ServerSession) ipcp(pkt cpPacket) error {
	switch pkt.Code {
	case codeConfigureRequest:
		opts, ok := parseOptions(pkt.Body)
		if !ok {
			return errors.New("ppp: malformed IPCP options")
		}
		var reject, nak []option
		hasAddress := false
		for _, opt := range opts {
			switch opt.Type {
			case optIPAddress:
				hasAddress = true
				if len(opt.Value) != 4 {
					return errors.New("ppp: malformed IP address")
				}
				if !net.IP(opt.Value).Equal(s.clientIP) {
					nak = append(nak, option{Type: optIPAddress, Value: s.clientIP})
				}
			case optPrimaryDNS, optSecondaryDNS:
				if s.dns == nil {
					reject = append(reject, opt)
				} else if !net.IP(opt.Value).Equal(s.dns) {
					nak = append(nak, option{Type: opt.Type, Value: s.dns})
				}
			default:
				reject = append(reject, opt)
			}
		}
		if !hasAddress {
			nak = append(nak, option{Type: optIPAddress, Value: s.clientIP})
		}
		if len(reject) > 0 {
			return s.send(ProtocolIPCP, cpPacket{Code: codeConfigureReject, ID: pkt.ID, Body: marshalOptions(reject)})
		}
		if len(nak) > 0 {
			s.naks++
			if s.naks > 8 {
				return errors.New("ppp: IPCP did not converge")
			}
			return s.send(ProtocolIPCP, cpPacket{Code: codeConfigureNak, ID: pkt.ID, Body: marshalOptions(nak)})
		}
		if err := s.send(ProtocolIPCP, cpPacket{Code: codeConfigureAck, ID: pkt.ID, Body: pkt.Body}); err != nil {
			return err
		}
		s.ipcpRemote = true
	case codeConfigureAck:
		if pkt.ID != s.ipcpID || !bytes.Equal(pkt.Body, s.ipcpRequest) {
			return errors.New("ppp: unexpected IPCP ack")
		}
		s.ipcpLocal = true
	case codeConfigureNak, codeConfigureReject:
		return fmt.Errorf("ppp: peer rejected required server IP configuration")
	}
	if !s.ready && s.ipcpLocal && s.ipcpRemote {
		s.ready = true
		s.phase = phaseUp
		s.handler.ServerNetworkUp()
	}
	return nil
}

// ServerAddress returns the server's negotiated IPv4 address.
func (s *ServerSession) ServerAddress() net.IP { return append(net.IP(nil), s.localIP...) }

// ClientAddress returns the IPv4 address reserved for this session.
func (s *ServerSession) ClientAddress() net.IP { return append(net.IP(nil), s.clientIP...) }
