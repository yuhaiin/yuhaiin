package sstp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/sstp/wire"
)

// sstpURI is the fixed SSTP endpoint every server exposes ([MS-SSTP] 2.2).
const sstpURI = "/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"

// sstpHandshake performs the SSTP HTTP-layer handshake over the TLS connection:
// an SSTP_DUPLEX_POST to the well-known URI (not an HTTP CONNECT) with a maximal
// Content-Length that marks the body as the effectively unbounded SSTP stream.
// The server answers 200 OK, after which the connection carries SSTP packets.
func sstpHandshake(conn io.ReadWriter, host string) error {
	correlationID, err := newCorrelationID()
	if err != nil {
		return err
	}
	req := "SSTP_DUPLEX_POST " + sstpURI + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"SSTPCORRELATIONID: " + correlationID + "\r\n" +
		"Content-Length: 18446744073709551615\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	status, err := readHTTPHeader(conn)
	if err != nil {
		return err
	}
	if !strings.Contains(status, " 200") {
		return fmt.Errorf("server rejected SSTP: %s", status)
	}
	return nil
}

// readHTTPHeader reads the response header block one byte at a time until the
// CRLFCRLF terminator and returns the status line. Reading unbuffered matters:
// the SSTP binary stream begins immediately after the header, so a buffered
// reader could swallow the first packet's bytes.
func readHTTPHeader(conn io.Reader) (status string, err error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", fmt.Errorf("read response: %w", err)
		}
		buf = append(buf, b[0])
		if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
			break
		}
		if len(buf) > 16384 {
			return "", fmt.Errorf("response header too large")
		}
	}
	if i := strings.Index(string(buf), "\r\n"); i >= 0 {
		return string(buf[:i]), nil
	}
	return string(buf), nil
}

// newCorrelationID returns a random GUID in the {XXXXXXXX-...} form SSTP servers
// expect for the SSTPCORRELATIONID header.
func newCorrelationID() (string, error) {
	var u [16]byte
	if _, err := rand.Read(u[:]); err != nil {
		return "", fmt.Errorf("correlation id: %w", err)
	}
	u[6] = (u[6] & 0x0f) | 0x40 // version 4
	u[8] = (u[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("{%08X-%04X-%04X-%04X-%012X}",
		u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]), nil
}

// sendCallConnectRequest sends SSTP_MSG_CALL_CONNECT_REQUEST. It carries only the
// Encapsulated Protocol ID attribute (PPP); the crypto-binding nonce is chosen by
// the server and returned in the Call Connect Ack, not requested here.
func sendCallConnectRequest(w io.Writer) error {
	attrs := []wire.Attribute{
		{ID: wire.AttrEncapsulatedProtocolID, Value: []byte{0x00, wire.ProtocolPPP}},
	}
	pkt, err := wire.EncodeControl(wire.MsgCallConnectRequest, attrs)
	if err != nil {
		return err
	}
	_, err = w.Write(pkt)
	return err
}

// readCallConnectAck reads the CallConnectAck response and returns the server's
// crypto-binding nonce. The nonce (MS-SSTP 2.2.3, Reserved(3) | HashBitmap(1) |
// Nonce(32)) is echoed back in the CallConnected message, so the client must use
// the server's value rather than generating its own.
func readCallConnectAck(r io.Reader) (nonce []byte, err error) {
	control, body, err := wire.ReadPacket(r)
	if err != nil {
		return nil, fmt.Errorf("read CallConnectAck: %w", err)
	}
	if !control {
		return nil, fmt.Errorf("expected a control packet")
	}
	msg, err := wire.ParseControl(body)
	if err != nil {
		return nil, fmt.Errorf("parse CallConnectAck: %w", err)
	}
	switch msg.Type {
	case wire.MsgCallConnectAck:
	case wire.MsgCallConnectNak:
		return nil, fmt.Errorf("server rejected the connection (CallConnectNak)")
	default:
		return nil, fmt.Errorf("unexpected response %#x", msg.Type)
	}

	cbr, ok := msg.Attribute(wire.AttrCryptoBindingReq)
	if !ok {
		return nil, fmt.Errorf("CallConnectAck missing the crypto-binding request")
	}
	if len(cbr.Value) < 4+wire.NonceLen {
		return nil, fmt.Errorf("%w: short crypto-binding request", wire.ErrMalformed)
	}
	if cbr.Value[3]&wire.CertHashSHA256 == 0 {
		return nil, fmt.Errorf("server does not offer SHA-256 crypto binding (bitmap %#x)", cbr.Value[3])
	}
	return append([]byte(nil), cbr.Value[4:4+wire.NonceLen]...), nil
}

// buildCallConnected builds a fully-formed SSTP_MSG_CALL_CONNECTED packet. The
// compound MAC covers the whole control message with its own MAC field zeroed, so
// the packet is built once with a zero MAC, the MAC is computed over the message
// body (everything after the 4-octet packet header), and its trailing bytes are
// patched in place.
func buildCallConnected(nonce, serverCertDER []byte, hlak [mschap.HLAKLen]byte) ([]byte, error) {
	cmk := DeriveCMK(hlak)
	certHash := sha256Sum(serverCertDER)

	val := BuildCBValue(nonce, certHash, make([]byte, wire.CompoundMACLen))
	pkt, err := wire.EncodeControl(wire.MsgCallConnected,
		[]wire.Attribute{{ID: wire.AttrCryptoBinding, Value: val}})
	if err != nil {
		return nil, err
	}

	// The compound MAC covers the whole packet — the 4-octet header included — with
	// the MAC field (built as zeros above) zeroed.
	mac := hmacSha256(cmk, pkt)
	copy(pkt[len(pkt)-wire.CompoundMACLen:], mac)
	return pkt, nil
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func hmacSha256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
