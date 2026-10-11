package fortinet

// The "GFtype" handshake that authorises a Fortinet DTLS flow.
//
// A certificate-based DTLS session proves who the *server* is, but not which
// authenticated client is on the other end -- the SVPNCOOKIE did that, over
// HTTPS. So the first application datagrams over a fresh DTLS session are this
// exchange: the client presents its cookie, and the server confirms. Only after
// it does PPP flow. The byte layouts are openconnect's, so veepin interoperates
// with the real client.

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// The fixed literals, each including their trailing NUL (C sizeof includes it).
// The client's carries the cookie after this prefix; the server's is answered
// with "ok".
var (
	gfClientHello = []byte("GFtype\x00clthello\x00SVPNCOOKIE\x00")
	gfServerHello = []byte("GFtype\x00svrhello\x00handshake\x00")
	gfServerOK    = []byte("ok")
)

// BuildDTLSClientHello builds the client's GFtype message: a 16-bit length (of
// the whole message, itself included), the clthello literal, the cookie, and a
// terminating NUL.
func BuildDTLSClientHello(cookie string) []byte {
	total := 2 + len(gfClientHello) + len(cookie) + 1
	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint16(out, uint16(total))
	out = append(out, gfClientHello...)
	out = append(out, cookie...)
	return append(out, 0)
}

// ParseDTLSClientHello extracts the cookie from a client's GFtype message.
func ParseDTLSClientHello(data []byte) (cookie string, err error) {
	if len(data) < 2 {
		return "", errors.New("fortinet: DTLS clthello too short")
	}
	total := int(binary.BigEndian.Uint16(data))
	if total != len(data) {
		return "", errors.New("fortinet: DTLS clthello length mismatch")
	}
	body := data[2:]
	if !bytes.HasPrefix(body, gfClientHello) {
		return "", errors.New("fortinet: DTLS clthello prefix mismatch")
	}
	// The cookie is NUL-terminated, as every field in this exchange is -- the
	// literals carry the terminator C's sizeof included. Requiring it means a
	// message has exactly one encoding, so a peer cannot present the same cookie
	// two ways.
	rest := body[len(gfClientHello):]
	if len(rest) == 0 || rest[len(rest)-1] != 0 {
		return "", errors.New("fortinet: DTLS clthello cookie is not NUL-terminated")
	}
	return string(rest[:len(rest)-1]), nil
}

// BuildDTLSServerHello builds the server's GFtype response: the svrhello literal
// followed by "ok".
func BuildDTLSServerHello() []byte {
	total := 2 + len(gfServerHello) + len(gfServerOK)
	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint16(out, uint16(total))
	out = append(out, gfServerHello...)
	return append(out, gfServerOK...)
}

// ParseDTLSServerHello reports whether a server GFtype response confirms the
// flow ("ok" after the svrhello literal).
func ParseDTLSServerHello(data []byte) error {
	if len(data) < 2 {
		return errors.New("fortinet: DTLS svrhello too short")
	}
	total := int(binary.BigEndian.Uint16(data))
	if total != len(data) {
		return errors.New("fortinet: DTLS svrhello length mismatch")
	}
	body := data[2:]
	if !bytes.HasPrefix(body, gfServerHello) {
		return errors.New("fortinet: DTLS svrhello prefix mismatch")
	}
	if !bytes.Equal(body[len(gfServerHello):], gfServerOK) {
		return errors.New("fortinet: DTLS server did not confirm the flow")
	}
	return nil
}
