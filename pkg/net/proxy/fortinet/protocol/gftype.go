package fortinet

// The client-side "GFtype" exchange authorises a Fortinet DTLS flow.
//
// A certificate-based DTLS session proves who the *server* is, but not which
// authenticated client is on the other end -- the SVPNCOOKIE did that, over
// HTTPS. So the first application datagrams over a fresh DTLS session are this
// exchange: the client presents its cookie, and the server confirms. Only after
// it does PPP flow. The byte layouts follow OpenConnect's client implementation.

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
