// Package l2tp implements the L2TP control and data channels (RFC 2661) that
// carry a PPP session over IPsec transport-mode ESP — the "L2TP/IPsec" a stock
// xl2tpd/strongSwan stack and every native-OS client speak.
//
// It provides both roles: the LAC (client, initiator) opens the tunnel and
// places the incoming call, and the LNS (server, responder) accepts them. The
// engine is transport-neutral: it writes finished L2TP datagrams through a send
// closure and is fed inbound datagrams by its owner, so the same Tunnel runs
// over a bare UDP socket (tests) or inside an ESP transport SA (production).
//
// This file is the wire codec: the L2TP header (RFC 2661 section 3.1) and the
// Attribute-Value Pair format (section 4.1). AVP hiding is not implemented — we
// never set a tunnel secret, so no AVP is obfuscated, and a hidden inbound AVP
// is rejected rather than silently mis-parsed.
package l2tp

import (
	"encoding/binary"
	"fmt"
)

// protocolVersion is the L2TP version nibble: 2 for RFC 2661.
const protocolVersion = 2

// Control-message types carried in the mandatory Message-Type AVP (attribute 0),
// RFC 2661 section 3.2. Only the subset a single-session tunnel needs is defined.
const (
	msgSCCRQ   = 1  // Start-Control-Connection-Request
	msgSCCRP   = 2  // Start-Control-Connection-Reply
	msgSCCCN   = 3  // Start-Control-Connection-Connected
	msgStopCCN = 4  // Stop-Control-Connection-Notification
	msgHELLO   = 6  // keepalive
	msgICRQ    = 10 // Incoming-Call-Request
	msgICRP    = 11 // Incoming-Call-Reply
	msgICCN    = 12 // Incoming-Call-Connected
	msgCDN     = 14 // Call-Disconnect-Notify
)

// AVP attribute types (RFC 2661 section 4.4), IETF vendor (Vendor ID 0).
const (
	avpMessageType         = 0
	avpProtocolVersion     = 2
	avpFramingCapabilities = 3
	avpHostName            = 7
	avpAssignedTunnelID    = 9
	avpReceiveWindowSize   = 10
	avpAssignedSessionID   = 14
	avpCallSerialNumber    = 15
	avpFramingType         = 19
	avpTxConnectSpeed      = 24
)

// header is a decoded L2TP header. The engine only ever emits control messages
// with the sequence numbers present (T=1,L=1,S=1) and data messages without
// (T=0,L=0,S=0), but the parser tolerates the optional fields on receive.
type header struct {
	isControl bool
	tunnelID  uint16
	sessionID uint16
	ns, nr    uint16 // valid only when hasSeq
	hasSeq    bool
	payload   []byte // AVPs (control) or PPP frame (data)
}

// L2TP header flag bits in the first octet (bit 0 is the most significant).
const (
	flagType   = 0x80 // T: 1 = control, 0 = data
	flagLength = 0x40 // L: Length field present
	flagSeq    = 0x08 // S: Ns/Nr present
	flagOffset = 0x02 // O: Offset Size present
)

// marshalControl builds a control-message datagram: the header with Length and
// the sequence numbers, followed by the AVP block.
func marshalControl(tunnelID, sessionID, ns, nr uint16, avps []byte) []byte {
	out := make([]byte, 12+len(avps))
	out[0] = flagType | flagLength | flagSeq
	out[1] = protocolVersion
	binary.BigEndian.PutUint16(out[2:], uint16(12+len(avps))) // Length covers the whole message
	binary.BigEndian.PutUint16(out[4:], tunnelID)
	binary.BigEndian.PutUint16(out[6:], sessionID)
	binary.BigEndian.PutUint16(out[8:], ns)
	binary.BigEndian.PutUint16(out[10:], nr)
	copy(out[12:], avps)
	return out
}

// marshalData builds a data-message datagram: a minimal header (no Length, no
// sequence) followed by the PPP frame. Peers accept the bare form and it keeps
// the per-packet overhead to six octets.
func marshalData(tunnelID, sessionID uint16, ppp []byte) []byte {
	out := make([]byte, 6+len(ppp))
	out[0] = 0 // T=0, L=0, S=0
	out[1] = protocolVersion
	binary.BigEndian.PutUint16(out[2:], tunnelID)
	binary.BigEndian.PutUint16(out[4:], sessionID)
	copy(out[6:], ppp)
	return out
}

// parseHeader decodes one L2TP datagram into its header and payload, handling the
// optional Length, sequence and offset fields per the flag octet.
func parseHeader(pkt []byte) (header, error) {
	if len(pkt) < 6 {
		return header{}, fmt.Errorf("l2tp: datagram too short (%d bytes)", len(pkt))
	}
	flags := pkt[0]
	if pkt[1]&0x0f != protocolVersion {
		return header{}, fmt.Errorf("l2tp: unsupported version %d", pkt[1]&0x0f)
	}
	h := header{isControl: flags&flagType != 0}
	off := 2
	// Length field, when present, precedes the tunnel/session IDs.
	var length int
	hasLength := flags&flagLength != 0
	if hasLength {
		if len(pkt) < off+2 {
			return header{}, fmt.Errorf("l2tp: truncated length field")
		}
		length = int(binary.BigEndian.Uint16(pkt[off:]))
		off += 2
	}
	if len(pkt) < off+4 {
		return header{}, fmt.Errorf("l2tp: truncated tunnel/session IDs")
	}
	h.tunnelID = binary.BigEndian.Uint16(pkt[off:])
	h.sessionID = binary.BigEndian.Uint16(pkt[off+2:])
	off += 4
	if flags&flagSeq != 0 {
		if len(pkt) < off+4 {
			return header{}, fmt.Errorf("l2tp: truncated sequence numbers")
		}
		h.ns = binary.BigEndian.Uint16(pkt[off:])
		h.nr = binary.BigEndian.Uint16(pkt[off+2:])
		h.hasSeq = true
		off += 4
	}
	if flags&flagOffset != 0 {
		if len(pkt) < off+2 {
			return header{}, fmt.Errorf("l2tp: truncated offset size")
		}
		off += 2 + int(binary.BigEndian.Uint16(pkt[off:])) // skip offset size + pad
	}
	// A control message with a Length field bounds its own payload; a bare data
	// message runs to the end of the datagram.
	end := len(pkt)
	if hasLength {
		if length < off || length > len(pkt) {
			return header{}, fmt.Errorf("l2tp: length %d out of range", length)
		}
		end = length
	}
	if off > end {
		return header{}, fmt.Errorf("l2tp: header overruns datagram")
	}
	h.payload = pkt[off:end]
	return h, nil
}

// avp is one decoded Attribute-Value Pair. Vendor ID is always 0 (IETF) for the
// attributes this implementation uses.
type avp struct {
	mandatory bool
	vendorID  uint16
	typ       uint16
	value     []byte
}

// avpBuilder accumulates AVPs for a control message in wire order; Message-Type
// must be added first (RFC 2661 section 4.1).
type avpBuilder struct {
	buf []byte
}

// add appends one AVP. Every AVP this engine sends is mandatory (M=1) and
// non-hidden (H=0), which is what a peer expects for the control attributes.
func (b *avpBuilder) add(typ uint16, value []byte) {
	const hdrLen = 6
	total := hdrLen + len(value)
	hdr := make([]byte, hdrLen)
	// M=1 (bit 0), H=0, reserved 0, then the 10-bit length in the low bits of the
	// first two octets.
	binary.BigEndian.PutUint16(hdr[0:], 0x8000|uint16(total&0x03ff))
	binary.BigEndian.PutUint16(hdr[2:], 0) // Vendor ID 0 (IETF)
	binary.BigEndian.PutUint16(hdr[4:], typ)
	b.buf = append(b.buf, hdr...)
	b.buf = append(b.buf, value...)
}

func (b *avpBuilder) addUint16(typ, v uint16) {
	var val [2]byte
	binary.BigEndian.PutUint16(val[:], v)
	b.add(typ, val[:])
}

func (b *avpBuilder) addUint32(typ uint16, v uint32) {
	var val [4]byte
	binary.BigEndian.PutUint32(val[:], v)
	b.add(typ, val[:])
}

func (b *avpBuilder) bytes() []byte { return b.buf }

// parseAVPs decodes the AVP block of a control message. It rejects hidden AVPs
// (H set): they require the tunnel secret we never negotiate, so an unhidden
// parse would be wrong rather than merely lossy.
func parseAVPs(body []byte) ([]avp, error) {
	var out []avp
	for len(body) > 0 {
		if len(body) < 6 {
			return nil, fmt.Errorf("l2tp: truncated AVP header")
		}
		flags := binary.BigEndian.Uint16(body[0:])
		length := int(flags & 0x03ff)
		if flags&0x4000 != 0 {
			return nil, fmt.Errorf("l2tp: hidden AVP not supported")
		}
		if length < 6 || length > len(body) {
			return nil, fmt.Errorf("l2tp: AVP length %d out of range", length)
		}
		out = append(out, avp{
			mandatory: flags&0x8000 != 0,
			vendorID:  binary.BigEndian.Uint16(body[2:]),
			typ:       binary.BigEndian.Uint16(body[4:]),
			value:     body[6:length],
		})
		body = body[length:]
	}
	return out, nil
}

// messageType returns the control message type from the mandatory Message-Type
// AVP (attribute 0), which RFC 2661 requires to be first.
func messageType(avps []avp) (uint16, bool) {
	for _, a := range avps {
		if a.vendorID == 0 && a.typ == avpMessageType && len(a.value) == 2 {
			return binary.BigEndian.Uint16(a.value), true
		}
	}
	return 0, false
}

// findAVP returns the value of the first IETF AVP of the given type.
func findAVP(avps []avp, typ uint16) ([]byte, bool) {
	for _, a := range avps {
		if a.vendorID == 0 && a.typ == typ {
			return a.value, true
		}
	}
	return nil, false
}

// findUint16 returns a 2-octet AVP value as a uint16.
func findUint16(avps []avp, typ uint16) (uint16, bool) {
	if v, ok := findAVP(avps, typ); ok && len(v) == 2 {
		return binary.BigEndian.Uint16(v), true
	}
	return 0, false
}
