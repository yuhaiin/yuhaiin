// Package ppp is a minimal PPP implementation for tunnelling IP over a datagram
// transport — the link SSTP carries inside its data packets. It provides both
// roles: the client (Session) does LCP link setup, MS-CHAPv2 authentication and
// IPCP to learn its assigned address and DNS; the server (ServerSession) is the
// authenticator — it opens LCP requiring MS-CHAPv2, challenges and verifies the
// client, and assigns the address over IPCP. It is transport-neutral (it sends
// and receives PPP frames through a Transport the caller supplies), so L2TP could
// drive it too.
//
// The framing follows RFC 1661, the control-protocol option format is shared by
// LCP (RFC 1661) and IPCP (RFC 1332), and authentication is MS-CHAPv2 (RFC 2759)
// via the internal/mschap package. There is no async-HDLC layer: the transport
// delimits frames, so a frame here is just the protocol number and its payload.
package ppp

// PPP protocol numbers (RFC 1661 and the "PPP DLL Protocol Numbers" registry).
const (
	ProtocolIP   = 0x0021
	ProtocolIPCP = 0x8021
	ProtocolLCP  = 0xc021
	ProtocolCHAP = 0xc223
)

// PPP HDLC address and control octets. Over SSTP there is no real HDLC layer,
// but Windows brackets each frame with these two octets unless Address-and-
// Control-Field-Compression was negotiated, so frames are parsed tolerant of
// their presence and always sent with them.
const (
	hdlcAddress = 0xff
	hdlcControl = 0x03
)

// frameHeaderLen is the address/control pair plus the 16-bit protocol number
// that opens every frame encodeFrame writes.
const frameHeaderLen = 4

// putFrameHeader writes the fixed prefix of a PPP frame into the front of b,
// which must have room for frameHeaderLen octets.
func putFrameHeader(b []byte, protocol uint16) {
	b[0] = hdlcAddress
	b[1] = hdlcControl
	b[2] = byte(protocol >> 8)
	b[3] = byte(protocol)
}

// encodeFrame builds a PPP frame: the HDLC address/control octets, the 16-bit
// protocol number, then the payload. The address/control pair is always sent
// (we never negotiate ACFC), which every server accepts.
func encodeFrame(protocol uint16, payload []byte) []byte {
	out := make([]byte, frameHeaderLen+len(payload))
	putFrameHeader(out, protocol)
	copy(out[frameHeaderLen:], payload)
	return out
}

// decodeFrame parses a received PPP frame into its protocol and payload,
// tolerating an optional leading address/control pair (ACFC) and a compressed
// single-octet protocol (PFC). It returns false if the frame is too short to
// carry a protocol number.
func decodeFrame(frame []byte) (protocol uint16, payload []byte, ok bool) {
	b := frame
	// Strip the address/control pair if present.
	if len(b) >= 2 && b[0] == hdlcAddress && b[1] == hdlcControl {
		b = b[2:]
	}
	if len(b) == 0 {
		return 0, nil, false
	}
	// A PPP protocol number is odd in its least significant octet. With Protocol-
	// Field-Compression a value below 256 is sent as a single (odd) octet.
	if b[0]&1 == 1 {
		return uint16(b[0]), b[1:], true
	}
	if len(b) < 2 {
		return 0, nil, false
	}
	return uint16(b[0])<<8 | uint16(b[1]), b[2:], true
}
