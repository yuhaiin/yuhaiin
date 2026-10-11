package dtls

import (
	"encoding/binary"
	"fmt"
)

// Handshake message bodies. Only what a PSK handshake needs is modelled: there
// are no certificate, certificate-request or key-share messages, and the only
// extension we emit is the one AnyConnect's PSK identity is carried by.

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

func parseClientHello(b []byte) (clientHello, error) {
	var m clientHello
	r := reader{b: b}
	m.version = r.uint16()
	m.random = r.bytes(randomLen)
	m.sessionID = r.vector8()
	m.cookie = r.vector8()
	suites := r.vector16()
	if r.err != nil {
		return m, fmt.Errorf("dtls: malformed ClientHello: %w", r.err)
	}
	if len(suites)%2 != 0 {
		return m, fmt.Errorf("dtls: malformed ClientHello cipher suite list")
	}
	for i := 0; i < len(suites); i += 2 {
		m.cipherSuites = append(m.cipherSuites, binary.BigEndian.Uint16(suites[i:]))
	}
	return m, nil
}

// helloVerifyRequest carries the stateless cookie a server uses to confirm the
// client owns its source address before it commits any memory (RFC 6347 section
// 4.2.1) — DTLS's defence against being used as an amplification reflector.
type helloVerifyRequest struct {
	version uint16
	cookie  []byte
}

func (m helloVerifyRequest) marshal() []byte {
	out := make([]byte, 0, 3+len(m.cookie))
	out = binary.BigEndian.AppendUint16(out, m.version)
	out = append(out, byte(len(m.cookie)))
	return append(out, m.cookie...)
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

// serverHello selects the version, suite and session.
type serverHello struct {
	version     uint16
	random      []byte
	sessionID   []byte
	cipherSuite uint16
}

func (m serverHello) marshal() []byte {
	out := make([]byte, 0, 64)
	out = binary.BigEndian.AppendUint16(out, m.version)
	out = append(out, m.random...)
	out = append(out, byte(len(m.sessionID)))
	out = append(out, m.sessionID...)
	out = binary.BigEndian.AppendUint16(out, m.cipherSuite)
	out = append(out, 0) // null compression
	return out
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

// pskIdentityHint is the server's optional ServerKeyExchange for a PSK suite: a
// hint naming which key to use. AnyConnect has exactly one, so the hint is empty,
// but the message is still sent because some stacks expect it.
type pskIdentityHint struct {
	hint []byte
}

func (m pskIdentityHint) marshal() []byte {
	out := make([]byte, 0, 2+len(m.hint))
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.hint)))
	return append(out, m.hint...)
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

func parsePSKClientKeyExchange(b []byte) (pskClientKeyExchange, error) {
	var m pskClientKeyExchange
	r := reader{b: b}
	m.identity = r.vector16()
	if r.err != nil {
		return m, fmt.Errorf("dtls: malformed ClientKeyExchange: %w", r.err)
	}
	return m, nil
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
