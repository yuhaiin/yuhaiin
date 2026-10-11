package pulse

// Authentication: the HTTP upgrade, the IF-T/TLS version exchange, and then EAP
// inside IF-T/TLS until the server hands out a session cookie.
//
//	client                                  server
//	  GET / … Upgrade: IF-T/TLS 1.0   -->
//	                                  <--   101 Switching Protocols
//	  TCG/VersionRequest              -->
//	                                  <--   TCG/VersionResponse
//	  Juniper/ClientInfo              -->
//	                                  <--   TCG/AuthChallenge (empty)
//	  EAP Response: Identity          -->
//	                                  <--   EAP Request: Juniper/1 (server info)
//	  EAP Response: Juniper/1 (AVPs)  -->
//	                                  <--   EAP Request: Juniper/1 { EAP-Message:
//	                                          EAP Request Juniper/2, PASSREQ }
//	  EAP Response: Juniper/1 {         -->
//	    username AVP, EAP-Message:
//	    EAP Response Juniper/2, password }
//	                                  <--   EAP Request: Juniper/1 { cookie AVP }
//	  EAP Response: Juniper/1 (empty) -->
//	                                  <--   TCG/AuthSuccess
//
// The nesting is genuinely four deep at its widest — EAP inside an AVP inside
// EAP inside IF-T/TLS inside TLS — and every layer carries its own length. The
// exact shapes below are what openconnect requires: it counts how many kinds of
// request a message carries and refuses anything that is not exactly one, so a
// server that helpfully sent the cookie alongside the password prompt would be
// refused rather than tolerated.

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// ErrAuth reports credentials the server rejected, so a caller can tell a bad
// password from a transport failure.
var ErrAuth = errors.New("pulse: authentication failed")

// UpgradeHeader is the value that turns an ordinary HTTPS request into an
// IF-T/TLS session.
const UpgradeHeader = "IF-T/TLS 1.0"

// versionPayload is the four-octet body of the version request: minimum 1,
// maximum 2, preferred 2. veepin speaks v1 authentication throughout, but a
// server will not offer HMAC-SHA256 for ESP unless the client claims v2 — which
// is why the real client claims it too.
var versionPayload = []byte{0x00, 0x01, 0x02, 0x02}

// stream is one IF-T/TLS connection with its outbound message counter. The
// counter is per-direction and purely informational — nothing rejects a gap —
// but a peer that logs it expects it to advance.
type stream struct {
	conn net.Conn
	br   *bufio.Reader
	seq  uint32
}

func newStream(conn net.Conn) *stream {
	return &stream{conn: conn, br: bufio.NewReaderSize(conn, 8192)}
}

// send writes one message, stamping and advancing the sequence number.
func (s *stream) send(vendor, msgType uint32, payload []byte) error {
	msg := EncodeMessage(vendor, msgType, s.seq, payload)
	s.seq++
	_, err := s.conn.Write(msg)
	return err
}

func (s *stream) sendLine(vendor, msgType uint32, line string) error {
	return s.send(vendor, msgType, append([]byte(line), 0))
}

// sendAuth writes one authentication message: the Auth Type word then an EAP
// packet.
func (s *stream) sendAuth(msgType uint32, eap []byte) error {
	payload := make([]byte, 4+len(eap))
	binary.BigEndian.PutUint32(payload[0:4], AuthTypeJuniper1)
	copy(payload[4:], eap)
	return s.send(VendorTCG, msgType, payload)
}

func (s *stream) recv() (Message, error) { return ReadMessage(s.br) }

// expect reads one message and checks its vendor and type, so a peer that
// answers the wrong question is reported with both.
func (s *stream) expect(vendor, msgType uint32) (Message, error) {
	m, err := s.recv()
	if err != nil {
		return Message{}, err
	}
	if m.Vendor != vendor || m.Type != msgType {
		return Message{}, fmt.Errorf("pulse: expected vendor %#x type %d, got vendor %#x type %d",
			vendor, msgType, m.Vendor, m.Type)
	}
	return m, nil
}

// --- client ---

// LoginInfo is what a completed authentication yields.
type LoginInfo struct {
	// Cookie is the session identifier ("DSID") the server issued.
	Cookie string
	// User is the name that authenticated.
	User string
}

// ClientAuth runs the whole authentication exchange over an established TLS
// connection, returning the session it opened. The connection is left ready for
// the configuration phase.
func ClientAuth(conn net.Conn, host, path, user, password, hostname string) (*stream, LoginInfo, error) {
	s := newStream(conn)
	if err := clientUpgrade(s, host, path); err != nil {
		return nil, LoginInfo{}, err
	}

	// Version exchange.
	if err := s.send(VendorTCG, TypeVersionRequest, versionPayload); err != nil {
		return nil, LoginInfo{}, err
	}
	if _, err := s.expect(VendorTCG, TypeVersionResponse); err != nil {
		return nil, LoginInfo{}, fmt.Errorf("pulse: version negotiation: %w", err)
	}

	// Client information, then the server's empty challenge that opens
	// authentication.
	if err := s.sendLine(VendorJuniper, TypeClientInfo,
		fmt.Sprintf("clientHostName=%s clientCapabilities={}\n", hostname)); err != nil {
		return nil, LoginInfo{}, err
	}
	if _, err := s.expect(VendorTCG, TypeAuthChallenge); err != nil {
		return nil, LoginInfo{}, fmt.Errorf("pulse: opening the authentication exchange: %w", err)
	}

	// EAP identity. The real identity travels later, in an AVP; this one is
	// always the literal "anonymous".
	if err := s.sendAuth(TypeAuthResponse, EncodeEAP(EAPResponse, 1, EAPTypeIdentity, []byte("anonymous"))); err != nil {
		return nil, LoginInfo{}, err
	}

	info := LoginInfo{User: user}
	sentClientInfo, sentCredentials := false, false
	for {
		m, err := s.recv()
		if err != nil {
			return nil, LoginInfo{}, err
		}
		if m.Vendor == VendorTCG && m.Type == TypeAuthSuccess {
			if info.Cookie == "" {
				return nil, LoginInfo{}, fmt.Errorf("%w: the server finished without issuing a session", ErrAuth)
			}
			return s, info, nil
		}
		if m.Vendor != VendorTCG || m.Type != TypeAuthChallenge {
			return nil, LoginInfo{}, fmt.Errorf("pulse: unexpected vendor %#x type %d during authentication", m.Vendor, m.Type)
		}
		eap, err := parseAuthMessage(m)
		if err != nil {
			return nil, LoginInfo{}, err
		}
		if eap.Code == EAPFailure {
			return nil, LoginInfo{}, fmt.Errorf("%w: the server rejected the credentials", ErrAuth)
		}
		if !eap.Expanded || eap.Subtype != JuniperSubtypeAVP {
			return nil, LoginInfo{}, errors.New("pulse: the server asked for an authentication method veepin cannot answer")
		}

		avps, err := ParseAVPs(eap.Data)
		if err != nil {
			return nil, LoginInfo{}, err
		}
		if c, ok := FindAVP(avps, AVPCookie); ok {
			// The cookie ends the conversation: acknowledge with an empty
			// response and wait for the success message.
			info.Cookie = string(c.Value)
			if err := s.sendAuth(TypeAuthResponse,
				EncodeEAPExpanded(EAPResponse, eap.Ident, JuniperSubtypeAVP, nil)); err != nil {
				return nil, LoginInfo{}, err
			}
			continue
		}

		inner, ok := innerPasswordRequest(avps)
		if !ok {
			// The first Juniper/1 message a server sends is its own
			// information — licensing, capabilities, a sign-in page name — and
			// asks nothing. The answer to it is the client's own description,
			// which is what draws out the password prompt.
			if !sentClientInfo {
				sentClientInfo = true
				if err := s.sendAuth(TypeAuthResponse,
					EncodeEAPExpanded(EAPResponse, eap.Ident, JuniperSubtypeAVP, clientInfoAVPs())); err != nil {
					return nil, LoginInfo{}, err
				}
				continue
			}
			return nil, LoginInfo{}, errors.New("pulse: the server asked something veepin does not understand")
		}
		if sentCredentials {
			// A second prompt after we already answered is the protocol's way
			// of saying the first answer was wrong.
			return nil, LoginInfo{}, fmt.Errorf("%w: the server asked for the password again", ErrAuth)
		}
		sentCredentials = true
		if err := s.sendAuth(TypeAuthResponse,
			EncodeEAPExpanded(EAPResponse, eap.Ident, JuniperSubtypeAVP,
				passwordResponse(inner.Ident, user, password))); err != nil {
			return nil, LoginInfo{}, err
		}
	}
}

// clientVersion is the version string veepin presents. A server that gates
// features on it — IPv6 is the documented one — looks for a "Pulse-Secure/"
// prefix and a recent enough number, so the real product's spelling is used with
// veepin named as the platform rather than impersonating a platform it is not.
const clientVersion = "Pulse-Secure/22.2.1.1295 (veepin)"

// clientInfoAVPs describe this client to the server. Nothing here authenticates
// anything; a server uses it for policy and logging.
func clientInfoAVPs() []byte {
	out := EncodeAVPString(AVPClientOS, "Linux")
	return append(out, EncodeAVPString(AVPUserAgent, clientVersion)...)
}

// innerPasswordRequest finds the password prompt: an EAP-Message AVP whose
// payload is an EAP request of Juniper's subtype 2.
func innerPasswordRequest(avps []AVP) (EAPPacket, bool) {
	a, ok := FindAVP(avps, AVPEAPMessage)
	if !ok {
		return EAPPacket{}, false
	}
	eap, err := ParseEAP(a.Value)
	if err != nil || eap.Code != EAPRequest || !eap.Expanded || eap.Subtype != JuniperSubtypePassword {
		return EAPPacket{}, false
	}
	if len(eap.Data) != 1 {
		return EAPPacket{}, false
	}
	switch eap.Data[0] {
	case PassRequest, PassRetry:
		return eap, true
	}
	return EAPPacket{}, false
}

// passwordResponse renders the credentials: the username in its own AVP, and
// the password inside an EAP response of Juniper's subtype 2, whose three-octet
// preamble is a fixed 0x02 0x02 followed by the password's length plus two.
func passwordResponse(ident uint8, user, password string) []byte {
	body := make([]byte, 3+len(password))
	body[0], body[1] = 0x02, 0x02
	body[2] = byte(len(password) + 2)
	copy(body[3:], password)

	inner := EncodeEAPExpanded(EAPResponse, ident, JuniperSubtypePassword, body)
	out := EncodeAVPString(AVPUsername, user)
	return append(out, encodeAVPRaw(AVPEAPMessage, inner)...)
}

// clientUpgrade performs the HTTP/1.1 upgrade that turns the TLS connection
// into an IF-T/TLS one.
func clientUpgrade(s *stream, host, path string) error {
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: " + UpgradeHeader + "\r\n" +
		"Content-Type: EAP\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := s.conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("pulse: sending the upgrade request: %w", err)
	}
	resp, err := http.ReadResponse(s.br, nil)
	if err != nil {
		return fmt.Errorf("pulse: reading the upgrade response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("%w: the server refused the connection with %s", ErrAuth, resp.Status)
		}
		return fmt.Errorf("pulse: the server answered %s, want 101 Switching Protocols", resp.Status)
	}
	return nil
}

// --- server ---

// Authenticator checks a username and password.
type Authenticator func(user, password string) bool

// ServerAuth answers the client side of the exchange above, returning the
// session it issued.
func ServerAuth(conn net.Conn, auth Authenticator) (*stream, LoginInfo, error) {
	s := newStream(conn)
	if err := serverUpgrade(s); err != nil {
		return nil, LoginInfo{}, err
	}

	if _, err := s.expect(VendorTCG, TypeVersionRequest); err != nil {
		return nil, LoginInfo{}, err
	}
	// The response carries the version actually chosen in its last octet.
	if err := s.send(VendorTCG, TypeVersionResponse, []byte{0x00, 0x00, 0x00, 0x01}); err != nil {
		return nil, LoginInfo{}, err
	}

	// The client information line is advisory; it is read to keep the stream in
	// step, and its contents are logged by the caller if it wants them.
	if _, err := s.expect(VendorJuniper, TypeClientInfo); err != nil {
		return nil, LoginInfo{}, err
	}

	// An authentication challenge with nothing in it but the Auth Type: the
	// message that says "begin".
	if err := s.sendAuth(TypeAuthChallenge, nil); err != nil {
		return nil, LoginInfo{}, err
	}

	// EAP identity. Its contents are the literal "anonymous" and are not the
	// identity that authenticates, so nothing is read out of it.
	m, err := s.expect(VendorTCG, TypeAuthResponse)
	if err != nil {
		return nil, LoginInfo{}, err
	}
	if eap, perr := parseAuthMessage(m); perr != nil {
		return nil, LoginInfo{}, perr
	} else if eap.Code != EAPResponse || eap.Type != EAPTypeIdentity {
		return nil, LoginInfo{}, errors.New("pulse: the client did not answer with an EAP identity")
	}

	// Server information. A real server sends licensing and capability AVPs
	// here; a client reads none of them, so one that names this implementation
	// is enough to keep the exchange in shape.
	ident := uint8(2)
	if err := s.sendAuth(TypeAuthChallenge, EncodeEAPExpanded(EAPRequest, ident, JuniperSubtypeAVP,
		EncodeAVPString(AVPSigninName, "veepin"))); err != nil {
		return nil, LoginInfo{}, err
	}
	if _, err := s.expect(VendorTCG, TypeAuthResponse); err != nil {
		return nil, LoginInfo{}, err
	}

	// The password prompt. It must be the *only* kind of request in this
	// message: a client counts them and refuses a mixture.
	ident++
	innerIdent := ident
	if err := s.sendAuth(TypeAuthChallenge, EncodeEAPExpanded(EAPRequest, ident, JuniperSubtypeAVP,
		encodeAVPRaw(AVPEAPMessage,
			EncodeEAPExpanded(EAPRequest, innerIdent, JuniperSubtypePassword, []byte{PassRequest})))); err != nil {
		return nil, LoginInfo{}, err
	}

	m, err = s.expect(VendorTCG, TypeAuthResponse)
	if err != nil {
		return nil, LoginInfo{}, err
	}
	user, password, err := credentialsFrom(m)
	if err != nil {
		return nil, LoginInfo{}, err
	}
	if auth == nil || !auth(user, password) {
		// Tell the client before hanging up, so it can say "wrong password"
		// rather than "the server stopped answering".
		_ = s.sendAuth(TypeAuthChallenge, EncodeEAPResult(EAPFailure, ident))
		return nil, LoginInfo{}, fmt.Errorf("%w: rejected user %q", ErrAuth, user)
	}

	// The cookie ends the conversation. Nothing else may travel with it.
	cookie, err := newCookie()
	if err != nil {
		return nil, LoginInfo{}, err
	}
	ident++
	if err := s.sendAuth(TypeAuthChallenge, EncodeEAPExpanded(EAPRequest, ident, JuniperSubtypeAVP,
		EncodeAVPString(AVPCookie, cookie))); err != nil {
		return nil, LoginInfo{}, err
	}
	if _, err := s.expect(VendorTCG, TypeAuthResponse); err != nil {
		return nil, LoginInfo{}, err
	}
	if err := s.sendAuth(TypeAuthSuccess, EncodeEAPResult(EAPSuccess, ident)); err != nil {
		return nil, LoginInfo{}, err
	}
	return s, LoginInfo{Cookie: cookie, User: user}, nil
}

// credentialsFrom reads the username AVP and the password out of the EAP
// message nested inside the response.
func credentialsFrom(m Message) (user, password string, err error) {
	eap, err := parseAuthMessage(m)
	if err != nil {
		return "", "", err
	}
	if !eap.Expanded || eap.Subtype != JuniperSubtypeAVP {
		return "", "", errors.New("pulse: the credential response is not a Juniper/1 EAP message")
	}
	avps, err := ParseAVPs(eap.Data)
	if err != nil {
		return "", "", err
	}
	if u, ok := FindAVP(avps, AVPUsername); ok {
		user = string(u.Value)
	}
	a, ok := FindAVP(avps, AVPEAPMessage)
	if !ok {
		return "", "", errors.New("pulse: the credential response carries no password")
	}
	inner, err := ParseEAP(a.Value)
	if err != nil {
		return "", "", err
	}
	if inner.Code != EAPResponse || !inner.Expanded || inner.Subtype != JuniperSubtypePassword {
		return "", "", errors.New("pulse: the credential response's inner EAP is not a password")
	}
	// The three-octet preamble is 0x02 0x02 followed by the length plus two;
	// the password is what follows, bounded by that length rather than by the
	// AVP, so a peer cannot claim more than it sent.
	if len(inner.Data) < 3 {
		return "", "", errors.New("pulse: truncated password response")
	}
	n := int(inner.Data[2]) - 2
	if n < 0 || n > len(inner.Data)-3 {
		return "", "", errors.New("pulse: password length disagrees with the message")
	}
	return user, string(inner.Data[3 : 3+n]), nil
}

// newCookie mints a session identifier. It is opaque to the client, which
// stores it as the "DSID" cookie and offers it back on a reconnect.
func newCookie() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("pulse: generating a session cookie: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// serverUpgrade answers the HTTP/1.1 upgrade.
//
// The request is read with net/http rather than by hand, because it is an
// ordinary well-formed request — unlike GlobalProtect's tunnel request, which
// has no headers at all and has to be split off in front of net/http.
func serverUpgrade(s *stream) error {
	req, err := http.ReadRequest(s.br)
	if err != nil {
		return fmt.Errorf("pulse: reading the upgrade request: %w", err)
	}
	_, _ = io.Copy(io.Discard, req.Body)
	_ = req.Body.Close()

	if !strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), UpgradeHeader) {
		_, _ = s.conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"))
		return fmt.Errorf("pulse: the client asked to upgrade to %q, not %q", req.Header.Get("Upgrade"), UpgradeHeader)
	}
	_, err = s.conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Content-Type: EAP\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: " + UpgradeHeader + "\r\n\r\n"))
	return err
}
