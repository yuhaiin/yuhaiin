// Package native implements the UDP control and data channels of L2TPv2/v3.
package native

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" // L2TP and CHAP specify MD5 on the wire.
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

const (
	msgSCCRQ = 1
	msgSCCRP = 2
	msgSCCCN = 3
	msgStop  = 4
	msgHello = 6
	msgICRQ  = 10
	msgICRP  = 11
	msgICCN  = 12
	msgCDN   = 14
	msgSLI   = 16
	msgACK   = 20
)

type avp struct {
	typ       uint16
	value     []byte
	mandatory bool
}

func attr(typ uint16, value []byte) avp { return avp{typ: typ, value: value, mandatory: true} }
func u16(n uint16) []byte               { return binary.BigEndian.AppendUint16(nil, n) }
func u32(n uint32) []byte               { return binary.BigEndian.AppendUint32(nil, n) }

type packet struct {
	version         int
	control         bool
	tunnel, session uint32
	ns, nr          uint16
	sequenced       bool
	avps            []avp
	payload         []byte
}

func (p packet) value(typ uint16) []byte {
	for _, a := range p.avps {
		if a.typ == typ {
			return a.value
		}
	}
	return nil
}
func (p packet) message() uint16 {
	if b := p.value(0); len(b) == 2 {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}
func (p packet) encode() []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, uint16(p.version)|0xc800)
	if p.version == 2 {
		binary.BigEndian.PutUint16(b[4:], uint16(p.tunnel))
		binary.BigEndian.PutUint16(b[6:], uint16(p.session))
	} else {
		binary.BigEndian.PutUint32(b[4:], p.tunnel)
	}
	binary.BigEndian.PutUint16(b[8:], p.ns)
	binary.BigEndian.PutUint16(b[10:], p.nr)
	for _, a := range p.avps {
		flags := uint16(len(a.value) + 6)
		if a.mandatory {
			flags |= 0x8000
		}
		b = binary.BigEndian.AppendUint16(b, flags)
		b = binary.BigEndian.AppendUint16(b, 0)
		b = binary.BigEndian.AppendUint16(b, a.typ)
		b = append(b, a.value...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func decode(b []byte, secret string) (packet, error) {
	var p packet
	if len(b) < 6 {
		return p, errors.New("l2tp: short header")
	}
	flags := binary.BigEndian.Uint16(b)
	p.version, p.control = int(flags&15), flags&0x8000 != 0
	if p.version != 2 && p.version != 3 {
		return p, errors.New("l2tp: unsupported wire version")
	}
	if !p.control && p.version == 3 {
		if len(b) < 8 {
			return p, errors.New("l2tpv3: short session header")
		}
		p.session, p.payload = binary.BigEndian.Uint32(b[4:]), b[8:]
		return p, nil
	}
	offset := 2
	if flags&0x4000 != 0 {
		n := int(binary.BigEndian.Uint16(b[2:]))
		if n < 6 || n > len(b) {
			return p, errors.New("l2tp: invalid packet length")
		}
		b, offset = b[:n], 4
	}
	if len(b) < offset+4 {
		return p, errors.New("l2tp: short identifiers")
	}
	if p.version == 2 {
		p.tunnel = uint32(binary.BigEndian.Uint16(b[offset:]))
		p.session = uint32(binary.BigEndian.Uint16(b[offset+2:]))
	} else {
		p.tunnel = binary.BigEndian.Uint32(b[offset:])
	}
	offset += 4
	p.sequenced = flags&0x0800 != 0
	if p.sequenced {
		if len(b) < offset+4 {
			return p, errors.New("l2tp: short sequence header")
		}
		p.ns, p.nr = binary.BigEndian.Uint16(b[offset:]), binary.BigEndian.Uint16(b[offset+2:])
		offset += 4
	}
	if p.control && (flags&0x4000 == 0 || !p.sequenced) {
		return p, errors.New("l2tp: control requires length and sequence")
	}
	if !p.control {
		if flags&0x0200 != 0 {
			if len(b) < offset+2 {
				return p, errors.New("l2tp: short offset header")
			}
			offset += 2 + int(binary.BigEndian.Uint16(b[offset:]))
			if offset > len(b) {
				return p, errors.New("l2tp: invalid payload offset")
			}
		}
		p.payload = b[offset:]
		return p, nil
	}
	var vector []byte
	for offset < len(b) {
		if len(b)-offset < 6 {
			return p, errors.New("l2tp: short AVP")
		}
		f, vendor, typ := binary.BigEndian.Uint16(b[offset:]), binary.BigEndian.Uint16(b[offset+2:]), binary.BigEndian.Uint16(b[offset+4:])
		n := int(f & 1023)
		if n < 6 || n > len(b)-offset {
			return p, errors.New("l2tp: invalid AVP length")
		}
		mandatory := f&0x8000 != 0
		known := vendor == 0 && knownAVP(typ, p.version) && f&0x3c00 == 0
		if !known && mandatory {
			return p, fmt.Errorf("l2tp: unknown mandatory AVP %d/%d", vendor, typ)
		}
		if known {
			value := bytes.Clone(b[offset+6 : offset+n])
			if f&0x4000 != 0 {
				var err error
				value, err = unhide(typ, value, secret, vector)
				if err != nil {
					return p, err
				}
			}
			if typ == 36 {
				vector = value
			}
			if typ != 36 {
				if p.value(typ) != nil {
					return p, fmt.Errorf("l2tp: duplicate AVP %d", typ)
				}
				p.avps = append(p.avps, avp{typ: typ, value: value, mandatory: mandatory})
			}
		}
		offset += n
	}
	if len(p.avps) > 0 && (p.avps[0].typ != 0 || len(p.avps[0].value) != 2) {
		return p, errors.New("l2tp: missing first message-type AVP")
	}
	return p, nil
}

func knownAVP(t uint16, version int) bool {
	if version == 2 {
		return t <= 39
	}
	switch t {
	case 0, 1, 5, 7, 8, 9, 10, 12, 15, 19, 21, 25, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 68, 69, 70, 71, 72, 73, 74:
		return true
	}
	return false
}

func unhide(typ uint16, value []byte, secret string, vector []byte) ([]byte, error) {
	if secret == "" || len(vector) == 0 || len(value) < 2 {
		return nil, errors.New("l2tp: hidden AVP without secret/vector")
	}
	plain := make([]byte, len(value))
	seed := append(u16(typ), []byte(secret)...)
	seed = append(seed, vector...)
	for i := 0; i < len(value); i += md5.Size {
		digest := md5.Sum(seed)
		for j := range min(md5.Size, len(value)-i) {
			plain[i+j] = value[i+j] ^ digest[j]
		}
		seed = append([]byte(secret), value[i:min(i+md5.Size, len(value))]...)
	}
	n := int(binary.BigEndian.Uint16(plain))
	if n > len(plain)-2 {
		return nil, errors.New("l2tp: invalid hidden AVP length")
	}
	return plain[2 : 2+n], nil
}

func challengeResponse(message byte, secret string, challenge []byte) []byte {
	h := md5.New()
	h.Write([]byte{message})
	h.Write([]byte(secret))
	h.Write(challenge)
	return h.Sum(nil)
}

func controlDigest(raw []byte, secret string, localNonce, remoteNonce []byte, verify bool) ([]byte, error) {
	if len(raw) < 35 {
		return nil, errors.New("l2tpv3: missing message digest")
	}
	// Message type occupies the first eight AVP octets; digest must follow it.
	start := 20
	f := binary.BigEndian.Uint16(raw[start:])
	n := int(f & 1023)
	if binary.BigEndian.Uint16(raw[start+2:]) != 0 || binary.BigEndian.Uint16(raw[start+4:]) != 59 || n > len(raw)-start {
		return nil, errors.New("l2tpv3: missing message digest")
	}
	var algorithm func() hash.Hash
	switch raw[start+6] {
	case 0:
		algorithm = md5.New
	case 1:
		algorithm = sha1.New
	default:
		return nil, errors.New("l2tpv3: unknown digest algorithm")
	}
	if n != 7+algorithm().Size() {
		return nil, errors.New("l2tpv3: invalid digest size")
	}
	wire := bytes.Clone(raw)
	actual := bytes.Clone(wire[start+7 : start+n])
	clear(wire[start+7 : start+n])
	k := hmac.New(md5.New, []byte(secret))
	k.Write([]byte{2})
	h := hmac.New(algorithm, k.Sum(nil))
	h.Write(localNonce)
	h.Write(remoteNonce)
	h.Write(wire)
	digest := h.Sum(nil)
	if verify && !hmac.Equal(actual, digest) {
		return nil, ErrAuth
	}
	copy(wire[start+7:start+n], digest)
	return wire, nil
}
