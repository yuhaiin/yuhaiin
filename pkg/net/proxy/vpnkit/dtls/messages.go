package dtls

import (
	"encoding/binary"
	"fmt"
)

// Handshake message bodies used by the AnyConnect PSK and Fortinet ECDHE client
// handshakes.

// clientHello is the client's opening message, and its retransmission carrying
// the server's cookie.
type clientHello struct {
	version      uint16
	random       []byte
	sessionID    []byte // AnyConnect puts the hex-decoded X-DTLS-App-ID here
	cookie       []byte
	cipherSuites []uint16
}

func (m clientHello) marshal() []byte {
	out := make([]byte, 0, 64)
	out = binary.BigEndian.AppendUint16(out, m.version)
	out = append(out, m.random...)
	out = append(out, byte(len(m.sessionID)))
	out = append(out, m.sessionID...)
	out = append(out, byte(len(m.cookie)))
	out = append(out, m.cookie...)
	out = binary.BigEndian.AppendUint16(out, uint16(2*len(m.cipherSuites)))
	for _, cs := range m.cipherSuites {
		out = binary.BigEndian.AppendUint16(out, cs)
	}
	// One compression method: null. Compression is not negotiable here.
	out = append(out, 1, 0)
	// No extensions: a PSK handshake with a fixed suite needs none, and omitting
	// the block entirely is valid.
	return out
}

// helloVerifyRequest carries the peer's cookie challenge (RFC 6347 section
// 4.2.1), which the client echoes in its next ClientHello.
type helloVerifyRequest struct {
	version uint16
	cookie  []byte
}

func parseHelloVerifyRequest(b []byte) (helloVerifyRequest, error) {
	var m helloVerifyRequest
	r := reader{b: b}
	m.version = r.uint16()
	m.cookie = r.vector8()
	if r.err != nil {
		return m, fmt.Errorf("dtls: malformed HelloVerifyRequest: %w", r.err)
	}
	return m, nil
}

// serverHello carries the peer's selected version, suite and session.
type serverHello struct {
	version     uint16
	random      []byte
	sessionID   []byte
	cipherSuite uint16
}

func parseServerHello(b []byte) (serverHello, error) {
	var m serverHello
	r := reader{b: b}
	m.version = r.uint16()
	m.random = r.bytes(randomLen)
	m.sessionID = r.vector8()
	m.cipherSuite = r.uint16()
	if r.err != nil {
		return m, fmt.Errorf("dtls: malformed ServerHello: %w", r.err)
	}
	return m, nil
}

// pskClientKeyExchange names the identity the client is authenticating with.
type pskClientKeyExchange struct {
	identity []byte
}

func (m pskClientKeyExchange) marshal() []byte {
	out := make([]byte, 0, 2+len(m.identity))
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.identity)))
	return append(out, m.identity...)
}

// reader is a bounds-checked cursor over a message body. Every accessor is a
// no-op once an error is latched, so a parse can be written as a straight run of
// reads with a single check at the end.
type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if r.off+n > len(r.b) {
		r.err = fmt.Errorf("need %d octets at offset %d, have %d", n, r.off, len(r.b))
		return false
	}
	return true
}

func (r *reader) uint16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *reader) bytes(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

// vector8 reads a vector with a one-octet length prefix.
func (r *reader) vector8() []byte {
	if !r.need(1) {
		return nil
	}
	n := int(r.b[r.off])
	r.off++
	return r.bytes(n)
}

// vector16 reads a vector with a two-octet length prefix.
func (r *reader) vector16() []byte {
	n := int(r.uint16())
	return r.bytes(n)
}
