// Package lightweight implements an IP-only userspace transport stack. It has
// no dependency on a TUN driver, gVisor or the application's proxy interfaces.
package lightweight

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	ErrMalformed   = errors.New("lightweight: malformed packet")
	ErrChecksum    = errors.New("lightweight: invalid checksum")
	ErrUnsupported = errors.New("lightweight: unsupported protocol or option")
	ErrLimit       = errors.New("lightweight: resource limit")
	ErrMTU         = errors.New("lightweight: packet exceeds path MTU")
)

// Packet borrows Data and Payload from the ParsePacket input, until its caller
// next changes that input. Parsing never allocates based on untrusted lengths.
type Packet struct {
	Source, Destination       netip.Addr
	Data, Payload             []byte
	Protocol, HopLimit        uint8
	Fragmented, MoreFragments bool
	FragmentID                uint32
	FragmentOffset            int
}

func ParsePacket(b []byte) (Packet, error) {
	var p Packet
	if len(b) < 1 {
		return p, ErrMalformed
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, ErrMalformed
		}
		h := int(b[0]&15) * 4
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if h < 20 || h > len(b) || n < h || n > len(b) || b[6]&0x80 != 0 {
			return p, ErrMalformed
		}
		if Checksum(b[:h]) != 0 {
			return p, ErrChecksum
		}
		if err := validateIPOptions(b[20:h], false); err != nil {
			return p, err
		}
		p.Source = netip.AddrFrom4([4]byte(b[12:16]))
		p.Destination = netip.AddrFrom4([4]byte(b[16:20]))
		p.Data = b[:n]
		p.Payload = b[h:n]
		p.Protocol = b[9]
		p.HopLimit = b[8]
		frag := binary.BigEndian.Uint16(b[6:8])
		p.FragmentOffset = int(frag&8191) * 8
		p.MoreFragments = frag&0x2000 != 0
		p.Fragmented = p.MoreFragments || p.FragmentOffset != 0
		p.FragmentID = uint32(binary.BigEndian.Uint16(b[4:6]))
		if p.Fragmented && (len(p.Payload) == 0 || p.MoreFragments && len(p.Payload)%8 != 0 || frag&0x4000 != 0 || p.FragmentOffset+len(p.Payload) > 65515) {
			return Packet{}, ErrMalformed
		}
	case 6:
		if len(b) < 40 {
			return p, ErrMalformed
		}
		n := 40 + int(binary.BigEndian.Uint16(b[4:6]))
		if n > len(b) {
			return p, ErrMalformed
		}
		p.Source = netip.AddrFrom16([16]byte(b[8:24]))
		p.Destination = netip.AddrFrom16([16]byte(b[24:40]))
		p.Data = b[:n]
		p.HopLimit = b[7]
		next := b[6]
		off := 40
		for count := 0; ; count++ {
			if count > 8 {
				return Packet{}, ErrMalformed
			}
			switch next {
			case 0, 60, 43:
				if off+2 > n || next == 0 && off != 40 {
					return Packet{}, ErrMalformed
				}
				size := (int(b[off+1]) + 1) * 8
				if off+size > n {
					return Packet{}, ErrMalformed
				}
				if next == 43 {
					if b[off+3] != 0 {
						return Packet{}, ErrUnsupported
					}
				} else if err := validateIPOptions(b[off+2:off+size], true); err != nil {
					return Packet{}, err
				}
				next = b[off]
				off += size
			case 44:
				if off+8 > n || b[off+1] != 0 {
					return Packet{}, ErrMalformed
				}
				f := binary.BigEndian.Uint16(b[off+2 : off+4])
				if f&6 != 0 {
					return Packet{}, ErrMalformed
				}
				p.Protocol = b[off]
				p.FragmentOffset = int(f & 0xfff8)
				p.MoreFragments = f&1 != 0
				p.FragmentID = binary.BigEndian.Uint32(b[off+4 : off+8])
				p.Payload = b[off+8 : n]
				p.Fragmented = true
				if p.MoreFragments && len(p.Payload)%8 != 0 || len(p.Payload) == 0 || p.FragmentOffset+len(p.Payload) > 65535 {
					return Packet{}, ErrMalformed
				}
				return p, nil
			case 50, 51:
				return Packet{}, ErrUnsupported // IPsec must terminate above this IP-only stack.
			default:
				p.Protocol = next
				p.Payload = b[off:n]
				return p, nil
			}
		}
	default:
		return p, ErrMalformed
	}
	return p, nil
}

func validateIPOptions(b []byte, v6 bool) error {
	for len(b) > 0 {
		kind := b[0]
		if !v6 && kind == 0 {
			return nil
		}
		if !v6 && kind == 1 || v6 && kind == 0 {
			b = b[1:]
			continue
		}
		if len(b) < 2 {
			return ErrMalformed
		}
		n := int(b[1])
		if v6 {
			n += 2
		}
		if n < 2 || n > len(b) {
			return ErrMalformed
		}
		if v6 {
			if kind&0xc0 != 0 {
				return ErrUnsupported
			}
		} else if kind == 131 || kind == 137 {
			return ErrUnsupported
		}
		b = b[n:]
	}
	return nil
}

func (p Packet) ValidateTransport() error {
	return p.validateTransport(false)
}
func (p Packet) validateTransport(checksumVerified bool) error {
	b := p.Payload
	if p.Fragmented {
		return ErrMalformed
	}
	switch p.Protocol {
	case 6:
		if len(b) < 20 || int(b[12]>>4)*4 < 20 || int(b[12]>>4)*4 > len(b) {
			return ErrMalformed
		}
	case 17:
		if len(b) < 8 || int(binary.BigEndian.Uint16(b[4:6])) != len(b) {
			return ErrMalformed
		}
		if binary.BigEndian.Uint16(b[6:8]) == 0 && !checksumVerified {
			if p.Source.Is4() {
				return nil
			}
			return ErrChecksum
		}
	case 1:
		if !p.Source.Is4() || len(b) < 8 {
			return ErrMalformed
		}
		if Checksum(b) != 0 {
			return ErrChecksum
		}
		return nil
	case 58:
		if !p.Source.Is6() || len(b) < 8 {
			return ErrMalformed
		}
	default:
		return ErrUnsupported
	}
	if (p.Protocol != 6 && p.Protocol != 17 || !checksumVerified) && transportChecksum(p.Source, p.Destination, p.Protocol, b) != 0 {
		return ErrChecksum
	}
	return nil
}

func ipHeaderSize(src, dst netip.Addr, payloadSize int) (int, error) {
	if !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() || src.Zone() != "" || dst.Zone() != "" {
		return 0, ErrMalformed
	}
	h := 40
	limit := 65535
	if src.Is4() {
		h = 20
		limit -= h
	}
	if payloadSize < 0 || payloadSize > limit {
		return 0, ErrMTU
	}
	return h, nil
}
func fillIPHeader(b []byte, src, dst netip.Addr, proto uint8, id uint16, h int) {
	clear(b[:h])
	if h == 20 {
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		binary.BigEndian.PutUint16(b[4:6], id)
		b[6] = 0x40
		b[8] = 64
		b[9] = proto
		copy(b[12:16], src.AsSlice())
		copy(b[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(b[10:12], Checksum(b[:20]))
	} else {
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-h))
		b[6] = proto
		b[7] = 64
		copy(b[8:24], src.AsSlice())
		copy(b[24:40], dst.AsSlice())
	}
}
func makeIP(src, dst netip.Addr, proto uint8, payload []byte, id uint16) ([]byte, error) {
	h, err := ipHeaderSize(src, dst, len(payload))
	if err != nil {
		return nil, err
	}
	b := make([]byte, h+len(payload))
	fillIPHeader(b, src, dst, proto, id, h)
	copy(b[h:], payload)
	return b, nil
}
