package l2tpv3

import (
	"encoding/binary"
	"errors"
)

// The L2TPv3 control connection (RFC 3931 section 3.2), over UDP.
//
//	 0                   1                   2                   3
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|T|L|x|x|S|x|x|x|x|x|x|x|  Ver  |             Length            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                     Control Connection ID                     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|               Ns              |               Nr              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                        AVPs ...
//
// Two things differ from the v2 control channel in internal/l2tp, and both are
// easy to carry over wrongly:
//
//   - The Control Connection ID is ONE 32-bit field. v2 has a 16-bit tunnel ID
//     and a 16-bit session ID; v3 control messages carry no session ID at all,
//     because sessions are named by AVPs instead.
//   - An acknowledgement is an explicit ACK MESSAGE (Message-Type 20), not v2's
//     zero-length body. A v3 peer sent a bare header with no AVPs would see a
//     malformed message, not an ack. (go-l2tp's transport.go sendExplicitAck
//     branches on exactly this; it is the difference the RFC text buries.)
//
// This file implements the QUIESCENT control connection only -- enough of the
// protocol to keep a static pseudowire alive and notice when it dies. See
// README.md for why the dynamic (SCCRQ/ICRQ) plane is not here.

const (
	// controlHeaderLen is flags/ver (2) + Length (2) + CCID (4) + Ns (2) + Nr (2).
	controlHeaderLen = 12
	// flagsVerControl is T=1, L=1, S=1, Ver=3 -- the only flag combination a v3
	// control message uses. Emitted verbatim, and required on receive.
	flagsVerControl = 0xc803
)

// Control message types (RFC 3931 section 3.1), the subset a quiescent
// connection needs.
const (
	msgStopCCN = 4  // Stop-Control-Connection-Notification
	msgHello   = 6  // keepalive
	msgAck     = 20 // explicit acknowledgement -- v3's replacement for the v2 ZLB
)

// AVP attribute types (RFC 3931 section 5.4), IETF vendor (Vendor ID 0).
const (
	avpMessageType = 0
	avpResultCode  = 1
)

// avpHeaderLen is flags/length (2) + Vendor ID (2) + Attribute Type (2).
const avpHeaderLen = 6

// avpMandatory is the M bit in the first octet of an AVP: a receiver that does
// not understand a mandatory AVP must tear the connection down.
const avpMandatory = 0x8000

// avpLengthMask is the 10-bit length field sharing the first 16-bit word with
// the M, H and reserved bits.
const avpLengthMask = 0x03ff

var (
	ErrControlShort   = errors.New("l2tpv3: control message shorter than its header")
	ErrControlFlags   = errors.New("l2tpv3: not a v3 control message")
	ErrControlLength  = errors.New("l2tpv3: control message length field out of range")
	ErrControlAVP     = errors.New("l2tpv3: malformed AVP")
	ErrControlHidden  = errors.New("l2tpv3: hidden AVP (no control-connection secret is configured)")
	ErrControlNoType  = errors.New("l2tpv3: control message does not begin with a Message-Type AVP")
	ErrControlUnknown = errors.New("l2tpv3: unhandled mandatory AVP")
)

// IsControl reports whether a datagram on the tunnel's UDP port is a control
// message rather than a data packet, by the T bit.
//
// Both layouts put a 32-bit identifier at offset 4 -- the Control Connection ID
// for control, the Session ID for data -- so nothing else in the packet
// distinguishes them. The T bit is the whole test.
func IsControl(pkt []byte) bool {
	return len(pkt) >= 2 && pkt[0]&0x80 != 0
}

// ControlMessage is a decoded control message.
type ControlMessage struct {
	CCID uint32
	Ns   uint16
	Nr   uint16
	// Type is the value of the leading Message-Type AVP. Every control message
	// must carry one first (RFC 3931 section 5.4.1).
	Type uint16
	// AVPs are the remaining attributes, in wire order, as subslices of the
	// input.
	AVPs []AVP
}

// AVP is one decoded Attribute-Value Pair.
type AVP struct {
	Mandatory bool
	VendorID  uint16
	Type      uint16
	Value     []byte // subslice of the input
}

// AppendControl encodes a control message carrying a single Message-Type AVP
// plus any extra AVPs already encoded in extra.
//
// ccid is the PEER's Control Connection ID -- what it told us to put on
// messages we send it, the same receiver-chooses convention the data cookie
// follows.
func AppendControl(dst []byte, ccid uint32, ns, nr uint16, msgType uint16, extra []byte) []byte {
	body := make([]byte, 0, avpHeaderLen+2+len(extra))
	body = appendAVP(body, avpMessageType, func(b []byte) []byte {
		return binary.BigEndian.AppendUint16(b, msgType)
	})
	body = append(body, extra...)

	total := controlHeaderLen + len(body)
	if cap(dst) < total {
		dst = make([]byte, total)
	}
	dst = dst[:total]

	binary.BigEndian.PutUint16(dst[0:], flagsVerControl)
	binary.BigEndian.PutUint16(dst[2:], uint16(total)) // Length covers the whole message
	binary.BigEndian.PutUint32(dst[4:], ccid)
	binary.BigEndian.PutUint16(dst[8:], ns)
	binary.BigEndian.PutUint16(dst[10:], nr)
	copy(dst[controlHeaderLen:], body)
	return dst
}

// appendAVP writes one mandatory, non-hidden IETF AVP whose value is produced
// by val. Every AVP this engine sends is mandatory (M=1) and non-hidden (H=0):
// no control-connection secret is configured, so nothing is obfuscated.
func appendAVP(dst []byte, typ uint16, val func([]byte) []byte) []byte {
	start := len(dst)
	dst = append(dst, 0, 0) // flags/length, filled in below
	dst = binary.BigEndian.AppendUint16(dst, 0)
	dst = binary.BigEndian.AppendUint16(dst, typ)
	dst = val(dst)
	binary.BigEndian.PutUint16(dst[start:], avpMandatory|uint16(len(dst)-start)&avpLengthMask)
	return dst
}

// ParseControl decodes one control message. AVP values are subslices of pkt.
func ParseControl(pkt []byte) (ControlMessage, error) {
	var m ControlMessage
	if len(pkt) < controlHeaderLen {
		return m, ErrControlShort
	}
	if binary.BigEndian.Uint16(pkt[0:]) != flagsVerControl {
		// A v3 control message always sets T, L and S together. Anything else
		// is a v2 message, a data packet, or noise.
		return m, ErrControlFlags
	}
	length := int(binary.BigEndian.Uint16(pkt[2:]))
	if length < controlHeaderLen || length > len(pkt) {
		return m, ErrControlLength
	}
	m.CCID = binary.BigEndian.Uint32(pkt[4:])
	m.Ns = binary.BigEndian.Uint16(pkt[8:])
	m.Nr = binary.BigEndian.Uint16(pkt[10:])

	avps, err := parseAVPs(pkt[controlHeaderLen:length])
	if err != nil {
		return m, err
	}
	if len(avps) == 0 || avps[0].Type != avpMessageType || avps[0].VendorID != 0 || len(avps[0].Value) != 2 {
		return m, ErrControlNoType
	}
	m.Type = binary.BigEndian.Uint16(avps[0].Value)
	m.AVPs = avps[1:]
	return m, nil
}

// parseAVPs walks an AVP block, returning subslices of it.
func parseAVPs(b []byte) ([]AVP, error) {
	var out []AVP
	for len(b) > 0 {
		if len(b) < avpHeaderLen {
			return nil, ErrControlAVP
		}
		word := binary.BigEndian.Uint16(b[0:])
		if word&0x4000 != 0 {
			// H bit: the value is obfuscated with a shared secret we do not
			// have. Rejecting is right -- parsing it as plaintext would feed
			// the state machine ciphertext.
			return nil, ErrControlHidden
		}
		n := int(word & avpLengthMask)
		if n < avpHeaderLen || n > len(b) {
			return nil, ErrControlAVP
		}
		out = append(out, AVP{
			Mandatory: word&avpMandatory != 0,
			VendorID:  binary.BigEndian.Uint16(b[2:]),
			Type:      binary.BigEndian.Uint16(b[4:]),
			Value:     b[avpHeaderLen:n],
		})
		b = b[n:]
	}
	return out, nil
}
