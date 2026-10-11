package dtls

// Peeking at an unprotected ClientHello.
//
// A server sharing one UDP socket across many clients has to decide which
// session a datagram belongs to before it can pick a key — and at that point
// nothing is authenticated yet. The first ClientHello carries a session-id, and
// AnyConnect puts the App-ID it handed out over HTTPS there precisely so the
// server can make that association.
//
// Everything read here is attacker-controlled and unauthenticated: it may only
// be used to *look up* a candidate session, never to grant anything. A forged
// App-ID gets an attacker as far as a handshake it cannot finish, because the
// PSK still has to match at Finished.

// ClientHelloSessionID extracts the session-id from a datagram that looks like
// an initial ClientHello, reporting false for anything else.
func ClientHelloSessionID(datagram []byte) ([]byte, bool) {
	hello, ok := peekClientHello(datagram)
	if !ok || len(hello.sessionID) == 0 {
		return nil, false
	}
	return hello.sessionID, true
}

// IsClientHello reports whether a datagram is an initial ClientHello. It is for
// a server whose sessions are not keyed by anything in the hello — Fortinet's
// certificate-based channel authorises the flow afterwards, with a cookie inside
// the established session, so all the demultiplexer needs to know here is that
// this datagram is plausibly the start of a handshake.
func IsClientHello(datagram []byte) bool {
	_, ok := peekClientHello(datagram)
	return ok
}

func peekClientHello(datagram []byte) (clientHello, bool) {
	rec, _, err := parseRecord(datagram)
	if err != nil || rec.typ != recordHandshake || rec.epoch != 0 {
		return clientHello{}, false
	}
	h, err := parseFragment(rec.fragment)
	if err != nil || h.typ != handshakeClientHello {
		return clientHello{}, false
	}
	// Only an unfragmented ClientHello is considered. A real one is far smaller
	// than any sane MTU, so a fragmented one is not worth reassembling before the
	// peer has proven anything.
	if h.offset != 0 || h.fragLen != h.length {
		return clientHello{}, false
	}
	hello, err := parseClientHello(h.body)
	if err != nil {
		return clientHello{}, false
	}
	return hello, true
}
