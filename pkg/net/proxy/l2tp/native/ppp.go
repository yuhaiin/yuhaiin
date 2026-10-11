package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

const (
	protoIPv4   = 0x21
	protoIPv6   = 0x57
	protoLCP    = 0xc021
	protoPAP    = 0xc023
	protoCHAP   = 0xc223
	protoIPCP   = 0x8021
	protoIPv6CP = 0x8057
)

type configure struct {
	peerID       byte
	peerOptions  []byte
	id           byte
	options      []byte
	ack, peerAck bool
	attempts     int
}
type pppState struct {
	running                                bool
	lcp, ipcp, ipv6cp                      configure
	auth                                   uint16
	algorithm                              byte
	authStarted, authenticated, ncpStarted bool
	papID                                  byte
	chapID                                 byte
	chapAuthenticator                      string
	peerIPv4, localIPv4                    netip.Addr
	localIID, peerIID                      [8]byte
	dns                                    [2]netip.Addr
}

func cp(code, id byte, value []byte) []byte {
	b := []byte{code, id, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(4+len(value)))
	return append(b, value...)
}
func options(b []byte) ([][]byte, error) {
	var opts [][]byte
	seen := make(map[byte]bool)
	for len(b) > 0 {
		if len(b) < 2 || b[1] < 2 || int(b[1]) > len(b) || seen[b[0]] {
			return nil, errors.New("l2tp: malformed PPP options")
		}
		n := int(b[1])
		opts = append(opts, b[:n])
		seen[b[0]] = true
		b = b[n:]
	}
	return opts, nil
}
func opt(typ byte, value []byte) []byte { return append([]byte{typ, byte(2 + len(value))}, value...) }

func (s *Session) negotiatePPP(ctx context.Context) error {
	var magic [4]byte
	_, _ = rand.Read(magic[:])
	p := &pppState{lcp: configure{options: append(opt(1, u16(uint16(s.cfg.MTU))), opt(5, magic[:])...)}}
	s.pppState = p
	_, _ = rand.Read(p.localIID[:])
	p.localIID[0] &= 0xfd
	if err := s.configure(protoLCP, &p.lcp); err != nil {
		return err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("l2tp: PPP negotiation: %w", ctx.Err())
		case <-s.done:
			return s.Err()
		case b := <-s.ppp:
			if err := s.handlePPP(b); err != nil {
				return err
			}
		case <-ticker.C:
			if err := s.retryPPP(); err != nil {
				return err
			}
		}
		if p.lcp.ack && p.lcp.peerAck {
			if p.auth == 0 {
				p.authenticated = true
			}
			if p.auth == protoPAP && !p.authStarted {
				p.authStarted = true
				p.papID++
				if err := s.sendPAP(); err != nil {
					return err
				}
			}
			if p.authenticated && !p.ncpStarted {
				p.ncpStarted = true
				p.ipcp.options = append(opt(3, []byte{0, 0, 0, 0}), opt(129, []byte{0, 0, 0, 0})...)
				p.ipcp.options = append(p.ipcp.options, opt(131, []byte{0, 0, 0, 0})...)
				if err := s.configure(protoIPCP, &p.ipcp); err != nil {
					return err
				}
				if s.cfg.IPv6 {
					p.ipv6cp.options = opt(1, p.localIID[:])
					if err := s.configure(protoIPv6CP, &p.ipv6cp); err != nil {
						return err
					}
				}
			}
		}
		if p.ipcp.ack && p.ipcp.peerAck && (!s.cfg.IPv6 || p.ipv6cp.ack && p.ipv6cp.peerAck) {
			if !p.localIPv4.Is4() || p.localIPv4.IsUnspecified() || p.localIPv4.IsMulticast() {
				return errors.New("l2tp: IPCP did not assign a unicast IPv4 address")
			}
			s.mu.Lock()
			s.info.Prefixes = []netip.Prefix{netip.PrefixFrom(p.localIPv4, 32)}
			s.info.PeerAddress = p.peerIPv4.String()
			for _, dns := range p.dns {
				if dns.IsValid() && !dns.IsUnspecified() {
					s.info.DNS = append(s.info.DNS, dns.String())
				}
			}
			if s.cfg.IPv6 {
				addr := [16]byte{0xfe, 0x80}
				copy(addr[8:], p.localIID[:])
				s.info.Prefixes = append(s.info.Prefixes, netip.PrefixFrom(netip.AddrFrom16(addr), 64))
				if s.cfg.IPv6Address != "" {
					prefix, _ := netip.ParsePrefix(s.cfg.IPv6Address)
					s.info.Prefixes = append(s.info.Prefixes, prefix)
				}
			}
			s.mu.Unlock()
			p.running = true
			s.wg.Go(s.maintainPPP)
			return nil
		}
	}
}

func (s *Session) configure(proto uint16, c *configure) error {
	c.id++
	c.ack = false
	c.attempts = 1
	return s.writePPP(proto, cp(1, c.id, c.options))
}

func (s *Session) sendPAP() error {
	b := append([]byte{byte(len(s.cfg.Username))}, []byte(s.cfg.Username)...)
	b = append(b, byte(len(s.cfg.Password)))
	b = append(b, []byte(s.cfg.Password)...)
	return s.writePPP(protoPAP, cp(1, s.pppState.papID, b))
}

func (s *Session) retryPPP() error {
	p := s.pppState
	for _, entry := range []struct {
		proto   uint16
		c       *configure
		enabled bool
	}{
		{protoLCP, &p.lcp, true}, {protoIPCP, &p.ipcp, p.ncpStarted}, {protoIPv6CP, &p.ipv6cp, p.ncpStarted && s.cfg.IPv6},
	} {
		if entry.enabled && !entry.c.ack {
			entry.c.attempts++
			if entry.c.attempts > 10 {
				return fmt.Errorf("l2tp: PPP %x configure retries exhausted", entry.proto)
			}
			if err := s.writePPP(entry.proto, cp(1, entry.c.id, entry.c.options)); err != nil {
				return err
			}
		}
	}
	if p.auth == protoPAP && p.authStarted && !p.authenticated {
		return s.sendPAP()
	}
	return nil
}

func (s *Session) handlePPP(frame []byte) error {
	proto, b, ok := decodePPP(frame)
	if !ok || len(b) < 4 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if n < 4 || n > len(b) {
		return nil
	}
	code, id, data := b[0], b[1], b[4:n]
	p := s.pppState
	if proto == protoPAP {
		if id != p.papID || !p.authStarted || p.auth != protoPAP {
			return nil
		}
		// SoftEther sends PAP ACK/NAK without the RFC 1334 message length byte.
		if len(data) > 0 && int(data[0])+1 > len(data) {
			return nil
		}
		if code == 3 {
			return ErrAuth
		}
		if code == 2 {
			p.authenticated = true
			s.mu.Lock()
			s.info.Auth = "pap"
			s.mu.Unlock()
		}
		return nil
	}
	if proto == protoCHAP {
		return s.handleCHAP(code, id, data)
	}
	var c *configure
	switch proto {
	case protoLCP:
		c = &p.lcp
	case protoIPCP:
		if !p.ncpStarted {
			return nil
		}
		c = &p.ipcp
	case protoIPv6CP:
		if !p.ncpStarted || !s.cfg.IPv6 {
			return s.rejectProtocol(proto, b[:n])
		}
		c = &p.ipv6cp
	default:
		return s.rejectProtocol(proto, b[:n])
	}
	switch code {
	case 1:
		if p.running {
			if id == c.peerID && bytes.Equal(data, c.peerOptions) {
				return s.writePPP(proto, cp(2, id, data))
			}
			return errors.New("l2tp: PPP peer requested renegotiation")
		}
		opts, err := options(data)
		if err != nil {
			return nil
		}
		var reject, nak []byte
		for _, o := range opts {
			if proto == protoLCP {
				switch o[0] {
				case 1:
					if len(o) != 4 {
						reject = append(reject, o...)
						continue
					}
					mru := int(binary.BigEndian.Uint16(o[2:]))
					if mru < 576 || s.cfg.IPv6 && mru < 1280 {
						nak = append(nak, opt(1, u16(uint16(s.cfg.MTU)))...)
						continue
					}
					s.info.MTU = min(s.cfg.MTU, mru)
				case 2:
					if len(o) != 6 {
						reject = append(reject, o...)
					}
				case 3:
					if len(o) < 4 {
						reject = append(reject, o...)
						continue
					}
					auth := binary.BigEndian.Uint16(o[2:])
					if auth == protoPAP && len(o) == 4 && (s.cfg.AuthType == "auto" || s.cfg.AuthType == "pap") {
						p.auth = auth
						p.algorithm = 0
					} else if auth == protoCHAP && len(o) == 5 && (o[4] == 5 || o[4] == 0x81) && (s.cfg.AuthType == "auto" || s.cfg.AuthType == "chap-md5" && o[4] == 5 || s.cfg.AuthType == "mschap-v2" && o[4] == 0x81) {
						p.auth = auth
						p.algorithm = o[4]
					} else {
						preferred := append(u16(protoCHAP), 5)
						if s.cfg.AuthType == "pap" {
							preferred = u16(protoPAP)
						}
						if s.cfg.AuthType == "mschap-v2" {
							preferred[2] = 0x81
						}
						nak = append(nak, opt(3, preferred)...)
					}
				case 5:
					if len(o) != 6 {
						reject = append(reject, o...)
					}
				case 7, 8:
					if len(o) != 2 {
						reject = append(reject, o...)
					}
				default:
					reject = append(reject, o...)
				}
			} else if proto == protoIPCP {
				if o[0] != 3 || len(o) != 6 {
					reject = append(reject, o...)
					continue
				}
				p.peerIPv4 = netip.AddrFrom4([4]byte(o[2:6]))
			} else {
				if o[0] != 1 || len(o) != 10 {
					reject = append(reject, o...)
					continue
				}
				if bytes.Equal(o[2:], make([]byte, 8)) || bytes.Equal(o[2:], p.localIID[:]) {
					var iid [8]byte
					_, _ = rand.Read(iid[:])
					nak = append(nak, opt(1, iid[:])...)
				} else {
					copy(p.peerIID[:], o[2:])
				}
			}
		}
		if len(reject) > 0 {
			return s.writePPP(proto, cp(4, id, reject))
		}
		if len(nak) > 0 {
			return s.writePPP(proto, cp(3, id, nak))
		}
		c.peerAck = true
		c.peerID, c.peerOptions = id, bytes.Clone(data)
		return s.writePPP(proto, cp(2, id, data))
	case 2:
		if id == c.id && bytes.Equal(data, c.options) {
			c.ack = true
		}
	case 3, 4:
		if id != c.id || c.ack {
			return nil
		}
		opts, err := options(data)
		if err != nil {
			return nil
		}
		current, _ := options(c.options)
		for _, received := range opts {
			index := slices.IndexFunc(current, func(o []byte) bool { return o[0] == received[0] })
			if index < 0 {
				return nil
			}
			if code == 4 {
				if !bytes.Equal(current[index], received) {
					return nil
				}
				if proto == protoIPCP && received[0] == 3 || proto == protoIPv6CP && received[0] == 1 {
					return errors.New("l2tp: peer rejected address negotiation")
				}
				current = slices.Delete(current, index, index+1)
			} else {
				if proto == protoLCP && received[0] == 1 {
					if len(received) != 4 {
						return nil
					}
					mru := int(binary.BigEndian.Uint16(received[2:]))
					if mru < 576 || mru > s.cfg.MTU || s.cfg.IPv6 && mru < 1280 {
						return errors.New("l2tp: invalid negotiated MRU")
					}
				} else if proto == protoIPCP {
					if len(received) != 6 {
						return nil
					}
				} else if proto == protoIPv6CP {
					if len(received) != 10 || bytes.Equal(received[2:], make([]byte, 8)) {
						return nil
					}
				}
				current[index] = bytes.Clone(received)
			}
		}
		c.options = nil
		for _, o := range current {
			c.options = append(c.options, o...)
		}
		if proto == protoIPCP {
			for _, o := range current {
				if len(o) != 6 {
					continue
				}
				addr := netip.AddrFrom4([4]byte(o[2:6]))
				switch o[0] {
				case 3:
					p.localIPv4 = addr
				case 129:
					p.dns[0] = addr
				case 131:
					p.dns[1] = addr
				}
			}
		}
		if proto == protoIPv6CP {
			for _, o := range current {
				if o[0] == 1 {
					copy(p.localIID[:], o[2:])
				}
			}
		}
		return s.configure(proto, c)
	case 5:
		_ = s.writePPP(proto, cp(6, id, data))
		return errors.New("l2tp: PPP peer terminated link")
	case 7, 8:
		if proto == protoLCP && code == 8 && len(data) >= 2 && binary.BigEndian.Uint16(data) == protoIPv6CP && s.cfg.IPv6 {
			return errors.New("l2tp: peer rejected IPv6CP")
		}
	case 9:
		if proto == protoLCP && p.lcp.ack && p.lcp.peerAck && len(data) >= 4 {
			body := bytes.Clone(data)
			for _, o := range mustOptions(p.lcp.options) {
				if o[0] == 5 && len(o) == 6 {
					copy(body[:4], o[2:])
				}
			}
			return s.writePPP(protoLCP, cp(10, id, body))
		}
	}
	return nil
}

func mustOptions(b []byte) [][]byte { o, _ := options(b); return o }
func (s *Session) rejectProtocol(proto uint16, b []byte) error {
	if !s.pppState.lcp.ack || !s.pppState.lcp.peerAck {
		return nil
	}
	return s.writePPP(protoLCP, cp(8, 0, append(u16(proto), b[:min(len(b), s.cfg.MTU-8)]...)))
}
func (s *Session) maintainPPP() {
	for {
		select {
		case <-s.done:
			return
		case b := <-s.ppp:
			if err := s.handlePPP(b); err != nil {
				s.fail(err)
				return
			}
		}
	}
}
