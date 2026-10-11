// Package masque implements MASQUE CONNECT-IP (RFC 9484): IP-over-HTTP/3.
//
// The HTTP/3 substrate lives in the http3 subpackage; this package is the
// CONNECT-IP protocol on top of it — the capsule types that assign an address
// and advertise a route, the HTTP-Datagram payload that carries an inner IP
// packet, and the client and server roles that turn a request stream into a
// tunnel.
//
// Because x/net/quic has no QUIC DATAGRAM frames, veepin runs in capsule mode:
// every inner packet is a DATAGRAM capsule on the request stream rather than an
// unreliable QUIC datagram. That is a documented performance boundary, not a
// correctness one; the capsule formats are identical either way. What capsule
// mode costs is reliability and ordering the tunnelled traffic did not ask for;
// what it must not also cost is allocation, which is why the data path uses the
// reusable DatagramEncoder and CapsuleReader at the bottom of this file.
package masque

import (
	"errors"
	"fmt"
	"io"

	"github.com/xen0bit/veepin/internal/masque/http3"
)

// Capsule type codes (RFC 9297 for DATAGRAM, RFC 9484 §4 for the rest).
const (
	CapsuleDatagram           = 0x00
	CapsuleAddressAssign      = 0x01
	CapsuleAddressRequest     = 0x02
	CapsuleRouteAdvertisement = 0x03
)

// maxCapsuleValue bounds a capsule this code will buffer. A DATAGRAM capsule
// carries one inner packet; the control capsules are a handful of addresses.
// 64 KiB is above any of these and stops a hostile length from forcing an
// unbounded allocation, the same ceiling the HTTP/3 frame layer uses.
const maxCapsuleValue = 1 << 16

// ErrCapsuleTooLarge reports a capsule whose length exceeds what will be
// buffered.
var ErrCapsuleTooLarge = errors.New("masque: capsule value exceeds the maximum")

// Capsule is a decoded capsule: its type and its value bytes.
type Capsule struct {
	Type  uint64
	Value []byte
}

// WriteCapsule writes one capsule as a type/length/value tuple. w is a
// RequestStream, whose Write delivers these bytes as one HTTP/3 DATA frame; the
// peer may reframe, which is why ReadCapsule streams rather than assuming the
// framing.
func WriteCapsule(w io.Writer, typ uint64, value []byte) error {
	hdr := http3.AppendVarint(nil, typ)
	hdr = http3.AppendVarint(hdr, uint64(len(value)))
	buf := append(hdr, value...)
	_, err := w.Write(buf)
	return err
}

// ReadCapsule reads one capsule from the capsule byte stream. A value larger
// than maxCapsuleValue is refused before it is allocated.
func ReadCapsule(r io.Reader) (Capsule, error) {
	typ, err := http3.ReadVarint(r)
	if err != nil {
		return Capsule{}, err
	}
	length, err := http3.ReadVarint(r)
	if err != nil {
		return Capsule{}, err
	}
	if length > maxCapsuleValue {
		return Capsule{}, fmt.Errorf("%w: %d octets", ErrCapsuleTooLarge, length)
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return Capsule{}, err
	}
	return Capsule{Type: typ, Value: value}, nil
}

// The allocation-free data path.
//
// WriteCapsule and ReadCapsule above are the straightforward forms, used where a
// capsule is sent once: the address handshake, a route advertisement. The data
// path cannot afford them. In capsule mode every tunnelled packet becomes a
// DATAGRAM capsule, so an allocation there is an allocation per packet, and the
// naive path allocated twice the packet's size to send it — a header buffer, a
// payload buffer, and a copy into each.
//
// These two types do the same encoding against buffers they own and reuse, so a
// steady-state tunnel allocates nothing per packet. The cost is that the buffer
// is borrowed rather than given: a value returned here is valid only until the
// next call on the same encoder or reader, which is exactly the discipline a
// per-connection read or write loop already has.

// DatagramEncoder builds DATAGRAM capsules carrying inner packets, reusing one
// buffer across calls. One encoder belongs to one write loop; it is not safe for
// concurrent use, which is why each loop owns its own rather than sharing.
type DatagramEncoder struct {
	buf []byte
}

// Encode returns the complete capsule for one inner packet: the DATAGRAM type,
// the length, the context ID, and the packet. The returned slice aliases the
// encoder's buffer and is only valid until the next Encode.
func (e *DatagramEncoder) Encode(packet []byte) []byte {
	return e.EncodePadded(packet, 0)
}

// EncodePadded is Encode with trailing filler after the inner packet, so the
// capsule reaches at least minInner octets of payload. A minInner at or below
// the packet's own length pads nothing, which is what Encode passes.
//
// The filler goes INSIDE the DATAGRAM capsule's value, after the IP packet, and
// that placement is what makes it inert. RFC 9484's context-0 payload is
// "context ID, then an IP packet" with no length of its own, so a receiver --
// ours or aioquic's -- hands everything after the context ID to its TUN and the
// kernel's IP stack delimits the real packet by the inner header's Total
// Length. This is the same mechanism WireGuard, L2TPv3, SoftEther and Nebula
// use; MASQUE needs no capsule type of its own for it.
//
// The alternative the docs used to suggest -- a filler capsule of an
// unregistered type, which RFC 9297 requires receivers to skip -- was rejected
// on the grounds that it tests the peer's compliance with a MUST rather than
// relying on behaviour every IP stack already has. A receiver that mishandles
// trailing octets is broken in a way a ping notices; a receiver that rejects an
// unknown capsule is merely non-compliant, and there would be no way to shape
// against it at all.
func (e *DatagramEncoder) EncodePadded(packet []byte, minInner int) []byte {
	inner := len(packet)
	if minInner > inner {
		inner = minInner
	}
	e.buf = e.buf[:0]
	e.buf = http3.AppendVarint(e.buf, CapsuleDatagram)
	e.buf = http3.AppendVarint(e.buf, uint64(http3.VarintLen(contextIDPackets)+inner))
	e.buf = http3.AppendVarint(e.buf, contextIDPackets)
	e.buf = append(e.buf, packet...)
	for range inner - len(packet) {
		e.buf = append(e.buf, 0)
	}
	return e.buf
}

// CapsuleReader reads capsules into a buffer it owns and reuses. Like the
// encoder it belongs to a single read loop and is not safe for concurrent use.
type CapsuleReader struct {
	hdr [8]byte // varint scratch, kept here so reading a header does not allocate
	buf []byte
}

// Read reads one capsule. The returned Capsule's Value aliases the reader's
// buffer and is only valid until the next Read — a caller that keeps it (a route
// advertisement it stores, say) must copy it first.
func (cr *CapsuleReader) Read(r io.Reader) (Capsule, error) {
	typ, err := cr.readVarint(r)
	if err != nil {
		return Capsule{}, err
	}
	length, err := cr.readVarint(r)
	if err != nil {
		return Capsule{}, err
	}
	if length > maxCapsuleValue {
		return Capsule{}, fmt.Errorf("%w: %d octets", ErrCapsuleTooLarge, length)
	}
	// The length is bounded above, so growing to it cannot be forced past the
	// ceiling; the buffer then settles at the largest capsule the peer sends.
	if uint64(cap(cr.buf)) < length {
		cr.buf = make([]byte, length)
	}
	value := cr.buf[:length]
	if _, err := io.ReadFull(r, value); err != nil {
		return Capsule{}, err
	}
	return Capsule{Type: typ, Value: value}, nil
}

// readVarint decodes one QUIC varint using the reader's own scratch space.
func (cr *CapsuleReader) readVarint(r io.Reader) (uint64, error) {
	if _, err := io.ReadFull(r, cr.hdr[:1]); err != nil {
		return 0, err
	}
	n := 1 << (cr.hdr[0] >> 6)
	v := uint64(cr.hdr[0] & 0x3f)
	if n == 1 {
		return v, nil
	}
	if _, err := io.ReadFull(r, cr.hdr[1:n]); err != nil {
		return 0, err
	}
	for _, c := range cr.hdr[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, nil
}
