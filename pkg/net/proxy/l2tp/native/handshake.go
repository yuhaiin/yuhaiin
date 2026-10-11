package native

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/binary"
	"errors"
)

func (s *Session) establish(ctx context.Context) error {
	if !s.cfg.Static {
		start := []avp{attr(7, []byte(s.cfg.Hostname)), attr(10, u16(1))}
		start[1].mandatory = false
		if s.cfg.Version == 2 {
			start = append(start, attr(2, u16(0x0100)), attr(3, u32(3)), attr(9, u16(uint16(s.localTunnel))), attr(4, u32(0)), attr(6, []byte("yuhaiin")))
			start[len(start)-1].typ, start[len(start)-1].mandatory = 8, false
			if len(s.localChallenge) > 0 {
				start = append(start, attr(11, s.localChallenge))
			}
		} else {
			start = []avp{attr(7, []byte(s.cfg.Hostname)), attr(60, u32(s.localTunnel)), attr(61, u32(s.localTunnel)), attr(62, u16(5)), attr(10, u16(1))}
			start[len(start)-1].mandatory = false // v3 receive-window type is 10 too.
			if len(s.localNonce) > 0 {
				start = append(start, attr(73, s.localNonce))
			}
		}
		if err := s.send(ctx, msgSCCRQ, 0, start...); err != nil {
			return err
		}
		reply, err := s.expect(ctx, msgSCCRP)
		if err != nil {
			return err
		}
		if len(reply.value(7)) == 0 {
			return errors.New("l2tp: peer omitted hostname")
		}
		if s.cfg.Version == 3 && len(reply.value(60)) != 4 {
			return errors.New("l2tpv3: peer omitted router ID")
		}
		connected := []avp{}
		if s.cfg.Version == 2 {
			if len(s.localChallenge) > 0 && !hmac.Equal(reply.value(13), challengeResponse(msgSCCRP, s.cfg.SharedSecret, s.localChallenge)) {
				return ErrAuth
			}
			if challenge := reply.value(11); len(challenge) > 0 {
				if s.cfg.SharedSecret == "" {
					return ErrAuth
				}
				connected = append(connected, attr(13, challengeResponse(msgSCCCN, s.cfg.SharedSecret, challenge)))
			}
		} else {
			caps := reply.value(62)
			found := false
			for i := 0; i+1 < len(caps); i += 2 {
				found = found || binary.BigEndian.Uint16(caps[i:]) == 5
			}
			if !found {
				return errors.New("l2tpv3: peer does not support Ethernet pseudowires")
			}
		}
		if err := s.send(ctx, msgSCCCN, 0, connected...); err != nil {
			return err
		}
		call := []avp{attr(14, u16(uint16(s.localSession))), attr(15, u32(randomID(3)))}
		if s.cfg.Version == 3 {
			sublayer := uint16(0)
			if s.cfg.Sublayer {
				sublayer = 1
			}
			call = []avp{attr(63, u32(s.localSession)), attr(64, u32(0)), attr(15, u32(randomID(3))), attr(68, u16(5)), attr(66, []byte(s.cfg.RemoteEndID)), attr(71, u16(3)), attr(65, s.localCookie), attr(69, u16(sublayer))}
		}
		if err := s.send(ctx, msgICRQ, 0, call...); err != nil {
			return err
		}
		reply, err = s.expect(ctx, msgICRP)
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.cfg.Version == 2 {
			id := reply.value(14)
			if len(id) != 2 || binary.BigEndian.Uint16(id) == 0 || reply.session != s.localSession {
				s.mu.Unlock()
				return errors.New("l2tp: invalid assigned session")
			}
			s.peerSession = uint32(binary.BigEndian.Uint16(id))
			for _, a := range reply.avps {
				if a.typ == 39 {
					if len(a.value) != 0 {
						s.mu.Unlock()
						return errors.New("l2tp: invalid sequencing-required AVP")
					}
					s.peerSequence = true
				}
			}
			connected = []avp{attr(24, u32(100000000)), attr(19, u32(1))}
		} else {
			id, remote := reply.value(63), reply.value(64)
			if len(id) != 4 || binary.BigEndian.Uint32(id) == 0 || len(remote) != 4 || binary.BigEndian.Uint32(remote) != s.localSession {
				s.mu.Unlock()
				return errors.New("l2tpv3: invalid session IDs")
			}
			status := reply.value(71)
			if len(status) != 2 || binary.BigEndian.Uint16(status)&1 == 0 {
				s.mu.Unlock()
				return errors.New("l2tpv3: peer Ethernet circuit is inactive")
			}
			s.peerSession = binary.BigEndian.Uint32(id)
			s.peerCookie = bytes.Clone(reply.value(65))
			if n := len(s.peerCookie); n != 0 && n != 4 && n != 8 {
				s.mu.Unlock()
				return errors.New("l2tpv3: invalid assigned cookie")
			}
			if sub := reply.value(69); len(sub) > 0 {
				if len(sub) != 2 || binary.BigEndian.Uint16(sub) > 1 {
					s.mu.Unlock()
					return errors.New("l2tpv3: unsupported sublayer")
				}
				s.peerSublayer = binary.BigEndian.Uint16(sub) == 1
			}
			if seq := reply.value(70); len(seq) > 0 {
				if len(seq) != 2 || binary.BigEndian.Uint16(seq) > 2 {
					s.mu.Unlock()
					return errors.New("l2tpv3: invalid data sequencing")
				}
				s.peerSequence = binary.BigEndian.Uint16(seq) != 0
				if s.peerSequence && !s.peerSublayer {
					s.mu.Unlock()
					return errors.New("l2tpv3: data sequencing requires sublayer")
				}
			}
			connected = []avp{attr(63, u32(s.localSession)), attr(64, u32(s.peerSession)), attr(71, u16(3))}
		}
		s.dataReady = true
		s.mu.Unlock()
		if err := s.send(ctx, msgICCN, s.peerSession, connected...); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.dataReady = true
	s.info.LocalTunnelID, s.info.PeerTunnelID, s.info.LocalSessionID, s.info.PeerSessionID = s.localTunnel, s.peerTunnel, s.localSession, s.peerSession
	s.mu.Unlock()
	if s.cfg.Version == 2 {
		return s.negotiatePPP(ctx)
	}
	return nil
}
