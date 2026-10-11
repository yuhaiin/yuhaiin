package native

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func (s *Session) receiveData(p packet) {
	s.mu.Lock()
	ready := s.dataReady
	cookie := s.localCookie
	s.mu.Unlock()
	if !ready || p.session != s.localSession || s.cfg.Version == 2 && p.tunnel != s.localTunnel {
		return
	}
	b := p.payload
	if s.cfg.Version == 3 {
		if !bytes.HasPrefix(b, cookie) {
			return
		}
		b = b[len(cookie):]
		if s.cfg.Sublayer {
			if len(b) < 4 {
				return
			}
			b = b[4:]
		}
		if len(b) < 14 || len(b) > s.cfg.MTU+14 {
			return
		}
	} else {
		proto, body, ok := decodePPP(b)
		if !ok {
			return
		}
		if proto != protoIPv4 && proto != protoIPv6 {
			select {
			case s.ppp <- bytes.Clone(b):
			default:
			} // Bound unauthenticated control traffic.
			return
		}
		b = body
		if !validIP(proto, b, s.cfg.MTU) {
			return
		}
	}
	select {
	case s.frames <- bytes.Clone(b):
	default:
	} // UDP loss semantics, bounded memory.
}

func validIP(proto uint16, b []byte, mtu int) bool {
	if len(b) == 0 || len(b) > mtu {
		return false
	}
	if proto == protoIPv4 {
		return len(b) >= 20 && b[0]>>4 == 4 && int(b[0]&15)*4 >= 20 && int(b[0]&15)*4 <= len(b) && int(binary.BigEndian.Uint16(b[2:])) == len(b)
	}
	return len(b) >= 40 && b[0]>>4 == 6 && 40+int(binary.BigEndian.Uint16(b[4:])) == len(b)
}

func (s *Session) ReadFrame() ([]byte, error) {
	select {
	case <-s.done:
		return nil, s.Err()
	case b := <-s.frames:
		return b, nil
	}
}

func (s *Session) WriteFrame(b []byte) error {
	if err := s.Err(); err != nil {
		return err
	}
	if s.cfg.Version == 2 {
		if len(b) == 0 {
			return errors.New("l2tp: empty IP packet")
		}
		proto := uint16(protoIPv4)
		if b[0]>>4 == 6 {
			proto = protoIPv6
		}
		if !validIP(proto, b, s.Info().MTU) {
			return errors.New("l2tp: invalid IP packet")
		}
		return s.writePPP(proto, b)
	}
	if len(b) < 14 || len(b) > s.cfg.MTU+14 {
		return errors.New("l2tpv3: invalid Ethernet frame size")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	wire := make([]byte, 8+len(s.peerCookie))
	binary.BigEndian.PutUint16(wire, 3)
	binary.BigEndian.PutUint32(wire[4:], s.peerSession)
	copy(wire[8:], s.peerCookie)
	if s.peerSublayer {
		seq := uint32(0)
		if s.peerSequence {
			seq = 0x40000000 | (s.dataSequence & 0xffffff)
			s.dataSequence++
		}
		wire = binary.BigEndian.AppendUint32(wire, seq)
	}
	s.mu.Unlock()
	return s.writeLocked(append(wire, b...))
}

func (s *Session) writePPP(proto uint16, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	header := 6
	flags := uint16(2)
	if s.peerSequence {
		header += 4
		flags |= 0x0800
	}
	wire := make([]byte, header+4)
	binary.BigEndian.PutUint16(wire, flags)
	binary.BigEndian.PutUint16(wire[2:], uint16(s.peerTunnel))
	binary.BigEndian.PutUint16(wire[4:], uint16(s.peerSession))
	if s.peerSequence {
		binary.BigEndian.PutUint16(wire[6:], uint16(s.dataSequence))
		s.dataSequence++
		binary.BigEndian.PutUint16(wire[8:], 0)
	}
	wire[header], wire[header+1] = 0xff, 3
	binary.BigEndian.PutUint16(wire[header+2:], proto)
	s.mu.Unlock()
	return s.writeLocked(append(wire, payload...))
}

func decodePPP(b []byte) (uint16, []byte, bool) {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 3 {
		b = b[2:]
	}
	if len(b) == 0 {
		return 0, nil, false
	}
	if b[0]&1 != 0 {
		return uint16(b[0]), b[1:], true
	}
	if len(b) < 2 || b[1]&1 == 0 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(b), b[2:], true
}
