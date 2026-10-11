package ikev1

import (
	"encoding/binary"
	"fmt"
)

// header is a decoded ISAKMP header (RFC 2408 section 3.1).
type header struct {
	initCookie [8]byte
	respCookie [8]byte
	exchange   uint8
	flags      uint8
	messageID  uint32
}

// payload is one generic payload: its type and its body (excluding the 4-octet
// generic payload header).
type payload struct {
	typ  uint8
	body []byte
}

// payloadChain renders a payload list as a generic-payload chain, wiring each
// Next Payload field from the following payload's type. It returns the first
// payload's type (for the header) and the chain bytes. An empty list yields
// payloadNone and no bytes.
func payloadChain(payloads []payload) (firstType uint8, chain []byte) {
	if len(payloads) == 0 {
		return payloadNone, nil
	}
	for i, p := range payloads {
		next := uint8(payloadNone)
		if i+1 < len(payloads) {
			next = payloads[i+1].typ
		}
		gh := []byte{next, 0, 0, 0}
		binary.BigEndian.PutUint16(gh[2:], uint16(4+len(p.body)))
		chain = append(chain, gh...)
		chain = append(chain, p.body...)
	}
	return payloads[0].typ, chain
}

// assemble frames an ISAKMP header around a body (a plaintext payload chain or an
// encrypted blob), filling in the first-payload type and total length.
func assemble(h header, firstPayload uint8, body []byte) []byte {
	out := make([]byte, isakmpHeaderLen+len(body))
	copy(out[0:8], h.initCookie[:])
	copy(out[8:16], h.respCookie[:])
	out[16] = firstPayload
	out[17] = isakmpVersion
	out[18] = h.exchange
	out[19] = h.flags
	binary.BigEndian.PutUint32(out[20:], h.messageID)
	binary.BigEndian.PutUint32(out[24:], uint32(len(out)))
	copy(out[isakmpHeaderLen:], body)
	return out
}

// marshalMessage renders a plaintext ISAKMP message: the header followed by the
// payload chain.
func marshalMessage(h header, payloads []payload) []byte {
	first, chain := payloadChain(payloads)
	return assemble(h, first, chain)
}

// parseHeader decodes the ISAKMP header and returns it, the first payload type,
// and the bytes following the header (payload chain or ciphertext).
func parseHeader(pkt []byte) (h header, firstPayload uint8, rest []byte, err error) {
	if len(pkt) < isakmpHeaderLen {
		return header{}, 0, nil, fmt.Errorf("ikev1: message shorter than header")
	}
	copy(h.initCookie[:], pkt[0:8])
	copy(h.respCookie[:], pkt[8:16])
	firstPayload = pkt[16]
	h.exchange = pkt[18]
	h.flags = pkt[19]
	h.messageID = binary.BigEndian.Uint32(pkt[20:])
	length := binary.BigEndian.Uint32(pkt[24:])
	if int(length) > len(pkt) || length < isakmpHeaderLen {
		return header{}, 0, nil, fmt.Errorf("ikev1: bad message length %d", length)
	}
	return h, firstPayload, pkt[isakmpHeaderLen:length], nil
}

// parsePayloads walks a generic payload chain starting with firstType, returning
// each payload's type and body plus the number of chain octets consumed (which
// excludes any trailing CBC padding after the last payload). It is used on the
// plaintext payload chain — for an encrypted message the caller decrypts first,
// then calls this. Returning consumed lets the caller hash the exact payload
// bytes rather than a reconstruction, which matters for cross-implementation
// Quick Mode HASH verification.
func parsePayloads(firstType uint8, chain []byte) (payloads []payload, consumed int, err error) {
	next := firstType
	for next != payloadNone {
		if len(chain)-consumed < 4 {
			return nil, 0, fmt.Errorf("ikev1: truncated payload header")
		}
		rem := chain[consumed:]
		thisType := next
		next = rem[0]
		plen := int(binary.BigEndian.Uint16(rem[2:]))
		if plen < 4 || plen > len(rem) {
			return nil, 0, fmt.Errorf("ikev1: payload length %d out of range", plen)
		}
		payloads = append(payloads, payload{typ: thisType, body: rem[4:plen]})
		consumed += plen
	}
	return payloads, consumed, nil
}

// findPayload returns the first payload of the given type.
func findPayload(payloads []payload, typ uint8) (payload, bool) {
	for _, p := range payloads {
		if p.typ == typ {
			return p, true
		}
	}
	return payload{}, false
}

// --- SA attributes (RFC 2408 section 3.3) ---

// attr is one SA attribute. Basic (TV) attributes carry a 2-octet value; variable
// (TLV) attributes carry an arbitrary-length value.
type attr struct {
	typ   uint16
	value []byte
	basic bool
}

func basicAttr(typ, val uint16) attr {
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, val)
	return attr{typ: typ, value: v, basic: true}
}

func varAttr(typ uint16, value []byte) attr {
	return attr{typ: typ, value: value}
}

func encodeAttrs(attrs []attr) []byte {
	var out []byte
	var word [2]byte
	for _, a := range attrs {
		if a.basic {
			binary.BigEndian.PutUint16(word[:], 0x8000|a.typ)
			out = append(out, word[:]...)
			out = append(out, a.value...) // exactly 2 octets
			continue
		}
		binary.BigEndian.PutUint16(word[:], a.typ&0x7fff)
		out = append(out, word[:]...)
		binary.BigEndian.PutUint16(word[:], uint16(len(a.value)))
		out = append(out, word[:]...)
		out = append(out, a.value...)
	}
	return out
}

func parseAttrs(b []byte) ([]attr, error) {
	var out []attr
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, fmt.Errorf("ikev1: truncated attribute")
		}
		afType := binary.BigEndian.Uint16(b)
		typ := afType & 0x7fff
		b = b[2:]
		if afType&0x8000 != 0 { // basic (TV)
			if len(b) < 2 {
				return nil, fmt.Errorf("ikev1: truncated basic attribute")
			}
			out = append(out, attr{typ: typ, value: append([]byte(nil), b[:2]...), basic: true})
			b = b[2:]
			continue
		}
		if len(b) < 2 {
			return nil, fmt.Errorf("ikev1: truncated attribute length")
		}
		l := int(binary.BigEndian.Uint16(b))
		b = b[2:]
		if l > len(b) {
			return nil, fmt.Errorf("ikev1: attribute value overruns")
		}
		out = append(out, attr{typ: typ, value: append([]byte(nil), b[:l]...)})
		b = b[l:]
	}
	return out, nil
}

// attrUint16 returns a basic attribute's value as a uint16.
func attrUint16(a attr) (uint16, bool) {
	if len(a.value) == 2 {
		return binary.BigEndian.Uint16(a.value), true
	}
	return 0, false
}

// findAttr returns the first attribute of the given type.
func findAttr(attrs []attr, typ uint16) (attr, bool) {
	for _, a := range attrs {
		if a.typ == typ {
			return a, true
		}
	}
	return attr{}, false
}
