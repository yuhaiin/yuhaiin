// Package anyconnect implements the Cisco AnyConnect SSL VPN protocol — the
// wire protocol OpenConnect and ocserv speak, written down as
// draft-mavrogiannopoulos-openconnect.
//
// The tunnel is established over HTTPS: an XML authentication exchange, then a
// CONNECT request whose response headers carry the client's address, netmask,
// DNS and routes. After that the same TLS connection carries IP packets in a
// trivial 8-octet framing (CSTP). Unlike SSTP, which negotiates addressing with
// a full PPP/IPCP session inside the tunnel, AnyConnect configures everything in
// HTTP headers, so no PPP is involved at all.
//
// A second, optional data channel runs DTLS over UDP on the same port; this
// package implements the TLS channel, which is a complete tunnel on its own and
// what the protocol falls back to whenever UDP is unavailable.
package anyconnect

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// CSTP packet framing (draft-mavrogiannopoulos-openconnect section 5):
//
//	 0      1      2      3      4      5      6      7
//	+------+------+------+------+------+------+------+------+
//	| 'S'  | 'T'  | 'F'  | 0x01 |  length (be16)   | type | 0x00 |
//	+------+------+------+------+------+------+------+------+
//
// length counts the payload following the header. The DTLS channel reuses the
// type byte alone, without this header, since a datagram needs no framing.
const (
	headerLen = 8
	// maxPayload bounds a single packet's payload. The length field is 16 bits,
	// so this is the protocol's own ceiling and doubles as the read-buffer size.
	maxPayload = 65535
)

// magic opens every CSTP packet.
var magic = [4]byte{'S', 'T', 'F', 0x01}

// Packet types (draft-mavrogiannopoulos-openconnect table 2).
const (
	typeData       = 0x00 // an IP packet
	typeDPDReq     = 0x03 // dead-peer-detection probe; the peer must echo it back
	typeDPDResp    = 0x04
	typeDisconnect = 0x05 // client is leaving; one reason octet follows
	typeKeepalive  = 0x07 // NAT/idle keepalive, no payload and no response
	typeCompressed = 0x08 // compressed data; veepin never negotiates compression
	typeTerminate  = 0x09 // server is shutting the session down
)

// marshal frames a payload as a CSTP packet.
func marshal(typ byte, payload []byte) []byte {
	out := make([]byte, headerLen+len(payload))
	copy(out, magic[:])
	binary.BigEndian.PutUint16(out[4:6], uint16(len(payload)))
	out[6] = typ
	// out[7] is reserved and stays zero.
	copy(out[headerLen:], payload)
	return out
}

// padPayload writes pkt into buf followed by target-len(pkt) zero octets and
// returns the padded payload, which shares buf's backing array. A target that
// does not exceed the packet, or that overflows buf, leaves pkt untouched.
//
// This is the downstream shaper's padding vehicle (dataplane/shape.go). Both
// framings length-delimit their payload — CSTP by its 16-bit length field, the
// DTLS channel by the datagram — so the filler needs nothing negotiated: the
// receiver delimits the real packet by the inner IP header's Total Length, as
// every IP stack must, Ethernet having padded short frames since forever.
//
// The tail is cleared on every call rather than only when it grows: a server's
// TUN is shared by every client, so filler left over from an earlier packet
// would send one client's bytes to another.
func padPayload(buf, pkt []byte, target int) []byte {
	if target <= len(pkt) || target > len(buf) {
		return pkt
	}
	copy(buf, pkt)
	clear(buf[len(pkt):target])
	return buf[:target]
}

// parseHeader validates a packet header and reports the type and payload length
// that follow it.
func parseHeader(hdr []byte) (typ byte, length int, err error) {
	if len(hdr) < headerLen {
		return 0, 0, errors.New("anyconnect: short packet header")
	}
	if hdr[0] != magic[0] || hdr[1] != magic[1] || hdr[2] != magic[2] || hdr[3] != magic[3] {
		return 0, 0, fmt.Errorf("anyconnect: bad packet magic %x", hdr[:4])
	}
	return hdr[6], int(binary.BigEndian.Uint16(hdr[4:6])), nil
}

// readPacket reads one whole CSTP packet from a buffered stream.
func readPacket(r io.Reader) (typ byte, payload []byte, err error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	typ, length, err := parseHeader(hdr[:])
	if err != nil {
		return 0, nil, err
	}
	if length == 0 {
		return typ, nil, nil
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}
