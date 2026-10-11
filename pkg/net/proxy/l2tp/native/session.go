package native

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

var ErrAuth = errors.New("l2tp: authentication rejected")

type Session struct {
	closeOnce                                          sync.Once
	cfg                                                Config
	conn                                               net.Conn
	mu                                                 sync.Mutex
	sendMu                                             sync.Mutex
	writeMu                                            sync.Mutex
	localTunnel, peerTunnel, localSession, peerSession uint32
	ns, nr, acknowledged                               uint16
	changed                                            chan struct{}
	controls                                           chan packet
	frames                                             chan []byte
	ppp                                                chan []byte
	done                                               chan struct{}
	err                                                error
	once                                               sync.Once
	wg                                                 sync.WaitGroup
	localNonce, remoteNonce                            []byte
	localChallenge                                     []byte
	localCookie, peerCookie                            []byte
	peerSublayer                                       bool
	peerSequence                                       bool
	dataSequence                                       uint32
	info                                               Info
	pppState                                           *pppState
	dataReady                                          bool
}

func randomID(version int) uint32 {
	var b [4]byte
	for {
		_, _ = rand.Read(b[:])
		v := binary.BigEndian.Uint32(b[:])
		if version == 2 {
			v &= 65535
		}
		if v != 0 {
			return v
		}
	}
}

func Connect(ctx context.Context, cfg Config, conn net.Conn) (*Session, error) {
	if err := cfg.Validate(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	s := &Session{cfg: cfg, conn: conn, localTunnel: randomID(cfg.Version), localSession: randomID(cfg.Version),
		changed: make(chan struct{}), controls: make(chan packet, 32), frames: make(chan []byte, 256), ppp: make(chan []byte, 64),
		done: make(chan struct{}), info: Info{MTU: cfg.MTU}}
	if cfg.Static {
		s.localTunnel = 0
		s.localSession, s.peerSession = cfg.LocalSessionID, cfg.PeerSessionID
		s.localCookie, s.peerCookie = bytes.Clone(cfg.LocalCookie), bytes.Clone(cfg.PeerCookie)
		s.peerSublayer = cfg.Sublayer
	} else if cfg.SharedSecret != "" {
		if cfg.Version == 2 {
			s.localChallenge = make([]byte, 16)
			_, _ = rand.Read(s.localChallenge)
		} else {
			s.localNonce = make([]byte, 32)
			_, _ = rand.Read(s.localNonce)
		}
	}
	if cfg.Version == 3 && !cfg.Static {
		s.localCookie = make([]byte, 8)
		_, _ = rand.Read(s.localCookie)
	}
	s.wg.Go(s.receive)
	stop := context.AfterFunc(ctx, func() { s.fail(ctx.Err()) })
	err := s.establish(ctx)
	stop()
	if err != nil {
		s.fail(err)
		s.wg.Wait()
		return nil, err
	}
	if err := s.Err(); err != nil {
		s.wg.Wait()
		return nil, err
	}
	if !cfg.Static {
		s.wg.Go(s.keepalive)
	}
	return s, nil
}

func (s *Session) expect(ctx context.Context, message uint16) (packet, error) {
	select {
	case <-ctx.Done():
		return packet{}, ctx.Err()
	case <-s.done:
		return packet{}, s.Err()
	case p := <-s.controls:
		if p.message() != message {
			return p, fmt.Errorf("l2tp: unexpected control message %d (want %d)", p.message(), message)
		}
		return p, nil
	}
}

func (s *Session) encodeControl(message uint16, session uint32, ns uint16, avps []avp) ([]byte, error) {
	p := packet{version: s.cfg.Version, control: true, tunnel: s.peerTunnel, session: session, ns: ns, nr: s.nr}
	if message != 0 {
		p.avps = append(p.avps, attr(0, u16(message)))
	}
	if s.cfg.Version == 3 && s.cfg.SharedSecret != "" {
		p.avps = append(p.avps, attr(59, make([]byte, 17)))
	}
	p.avps = append(p.avps, avps...)
	wire := p.encode()
	if s.cfg.Version == 3 && s.cfg.SharedSecret != "" {
		local, remote := s.localNonce, s.remoteNonce
		if message == msgSCCRQ {
			local, remote = nil, nil
		}
		return controlDigest(wire, s.cfg.SharedSecret, local, remote, false)
	}
	return wire, nil
}

// One outstanding message respects even a peer receive window of one. Loss is
// retried with exponential backoff; Ns stays fixed and Nr reflects fresh ACKs.
func (s *Session) send(ctx context.Context, message uint16, session uint32, avps ...avp) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	ns := s.ns
	s.ns++
	s.mu.Unlock()
	for attempt := range 7 {
		s.mu.Lock()
		wire, err := s.encodeControl(message, session, ns, avps)
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if err = s.write(wire); err != nil {
			return err
		}
		timer := time.NewTimer(min(time.Second<<attempt, 8*time.Second))
		for {
			s.mu.Lock()
			ack, changed := s.acknowledged, s.changed
			s.mu.Unlock()
			if int16(ack-(ns+1)) >= 0 {
				timer.Stop()
				return nil
			}
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-s.done:
				timer.Stop()
				return s.Err()
			case <-changed:
				continue
			case <-timer.C:
			}
			break
		}
	}
	return errors.New("l2tp: control retransmissions exhausted")
}

func (s *Session) receive() {
	buf := make([]byte, 65535)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			s.fail(err)
			return
		}
		p, err := decode(buf[:n], s.cfg.SharedSecret)
		if err != nil || p.version != s.cfg.Version {
			continue
		}
		if !p.control {
			s.receiveData(p)
			continue
		}
		if s.cfg.Static || p.tunnel != s.localTunnel {
			continue
		}
		s.mu.Lock()
		if s.cfg.Version == 3 && s.cfg.SharedSecret != "" {
			remote := s.remoteNonce
			if p.message() == msgSCCRP {
				remote = p.value(73)
			}
			if len(remote) == 0 {
				s.mu.Unlock()
				continue
			}
			if _, err := controlDigest(buf[:int(binary.BigEndian.Uint16(buf[2:]))], s.cfg.SharedSecret, remote, s.localNonce, true); err != nil {
				s.mu.Unlock()
				continue
			}
		}
		if p.message() == msgSCCRP && s.peerTunnel == 0 {
			id := p.value(9)
			if s.cfg.Version == 3 {
				id = p.value(61)
			}
			if s.cfg.Version == 2 && len(id) == 2 {
				s.peerTunnel = uint32(binary.BigEndian.Uint16(id))
			}
			if s.cfg.Version == 3 && len(id) == 4 {
				s.peerTunnel = binary.BigEndian.Uint32(id)
			}
			if s.peerTunnel == 0 || p.ns != 0 {
				s.peerTunnel = 0
				s.mu.Unlock()
				continue
			}
			if s.cfg.Version == 2 && len(s.localChallenge) > 0 && !hmac.Equal(p.value(13), challengeResponse(msgSCCRP, s.cfg.SharedSecret, s.localChallenge)) {
				s.mu.Unlock()
				s.fail(ErrAuth)
				return
			}
			s.remoteNonce = bytes.Clone(p.value(73))
			if peer, ok := s.conn.(interface{ ConfirmPeer() }); ok {
				peer.ConfirmPeer()
			}
		}
		if int16(p.nr-s.acknowledged) > 0 && int16(s.ns-p.nr) >= 0 {
			s.acknowledged = p.nr
			close(s.changed)
			s.changed = make(chan struct{})
		}
		ackOnly := len(p.avps) == 0 || s.cfg.Version == 3 && p.message() == msgACK
		accepted := !ackOnly && p.ns == s.nr
		if accepted {
			s.nr++
		}
		var ack []byte
		if !ackOnly {
			message := uint16(0)
			if s.cfg.Version == 3 {
				message = msgACK
			}
			ack, err = s.encodeControl(message, 0, s.ns, nil)
		}
		s.mu.Unlock()
		if err != nil {
			s.fail(err)
			return
		}
		if ack != nil {
			if err = s.write(ack); err != nil {
				s.fail(err)
				return
			}
		}
		if !accepted {
			continue
		}
		switch p.message() {
		case msgHello, msgSLI:
			continue
		case msgStop, msgCDN:
			s.fail(fmt.Errorf("l2tp: peer terminated session (result %x)", p.value(1)))
			return
		default:
			select {
			case s.controls <- p:
			default:
				s.fail(errors.New("l2tp: control queue overflow"))
				return
			}
		}
	}
}

func (s *Session) keepalive() {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := s.send(ctx, msgHello, 0)
		cancel()
		if err != nil {
			s.fail(err)
			return
		}
	}
}

func (s *Session) write(b []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.writeLocked(b)
}

func (s *Session) writeLocked(b []byte) error {
	n, err := s.conn.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}

func (s *Session) fail(err error) {
	s.once.Do(func() { s.mu.Lock(); s.err = err; s.mu.Unlock(); close(s.done); _ = s.conn.Close() })
}
func (s *Session) Err() error            { s.mu.Lock(); defer s.mu.Unlock(); return s.err }
func (s *Session) Done() <-chan struct{} { return s.done }
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		if !s.cfg.Static && s.Err() == nil {
			_ = s.conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
			s.mu.Lock()
			assigned := attr(9, u16(uint16(s.localTunnel)))
			if s.cfg.Version == 3 {
				assigned = attr(61, u32(s.localTunnel))
			}
			wire, err := s.encodeControl(msgStop, 0, s.ns, []avp{attr(1, u16(1)), assigned})
			s.mu.Unlock()
			if err == nil {
				_ = s.write(wire)
			}
		}
		s.fail(net.ErrClosed)
	})
	s.wg.Wait()
	return nil
}
func (s *Session) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	info := s.info
	info.Prefixes = slices.Clone(info.Prefixes)
	info.DNS = slices.Clone(info.DNS)
	return info
}
