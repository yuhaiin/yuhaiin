package masque

// The CONNECT-IP payloads (RFC 9484): the datagram that carries an inner IP
// packet, the address-assignment handshake, and route advertisement.
//
// Each of these is the *value* of a capsule; the capsule TLV framing is in
// capsule.go. The wire layouts here are transcribed from RFC 9484 §4 and are
// asserted byte-for-byte in the tests, because a field-width mistake in an
// address encoding is exactly the kind of thing that round-trips against itself
// and fails against a real proxy.

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/xen0bit/veepin/internal/masque/http3"
)

// contextIDPackets is the HTTP-Datagram context ID reserved for full IP packets
// (RFC 9484 §7). veepin negotiates no other context, so this is the only one it
// sends or accepts.
const contextIDPackets = 0

var errMalformed = errors.New("masque: malformed CONNECT-IP payload")

// EncodeDatagramPayload builds the payload of a DATAGRAM capsule carrying one
// inner IP packet: the reserved context ID 0 followed by the packet.
func EncodeDatagramPayload(ip []byte) []byte {
	out := http3.AppendVarint(nil, contextIDPackets)
	return append(out, ip...)
}

// DecodeDatagramPayload extracts the inner IP packet from a DATAGRAM capsule
// payload. A context ID other than 0 is not an error but is not an IP packet
// either, so it is reported as such for the caller to drop.
func DecodeDatagramPayload(payload []byte) (ip []byte, ok bool, err error) {
	ctx, rest, err := http3.ConsumeVarint(payload)
	if err != nil {
		return nil, false, err
	}
	if ctx != contextIDPackets {
		return nil, false, nil
	}
	return rest, true, nil
}

// AddressEntry is one assigned or requested address (RFC 9484 §4.1, §4.2). The
// two capsules share this layout exactly.
type AddressEntry struct {
	RequestID uint64
	Prefix    netip.Prefix
}

// appendAddress encodes one Request ID / IP Version / IP Address / Prefix Length
// group. The address width follows the version: four octets for v4, sixteen for
// v6, with nothing in between.
func appendAddress(dst []byte, e AddressEntry) []byte {
	dst = http3.AppendVarint(dst, e.RequestID)
	addr := e.Prefix.Addr()
	if addr.Is4() {
		dst = append(dst, 4)
		b := addr.As4()
		dst = append(dst, b[:]...)
	} else {
		dst = append(dst, 6)
		b := addr.As16()
		dst = append(dst, b[:]...)
	}
	return append(dst, byte(e.Prefix.Bits()))
}

// consumeAddress decodes one address group and returns the rest.
func consumeAddress(b []byte) (AddressEntry, []byte, error) {
	id, b, err := http3.ConsumeVarint(b)
	if err != nil {
		return AddressEntry{}, nil, err
	}
	if len(b) < 1 {
		return AddressEntry{}, nil, errMalformed
	}
	version := b[0]
	b = b[1:]

	var addr netip.Addr
	switch version {
	case 4:
		if len(b) < 4 {
			return AddressEntry{}, nil, errMalformed
		}
		addr = netip.AddrFrom4([4]byte(b[:4]))
		b = b[4:]
	case 6:
		if len(b) < 16 {
			return AddressEntry{}, nil, errMalformed
		}
		addr = netip.AddrFrom16([16]byte(b[:16]))
		b = b[16:]
	default:
		return AddressEntry{}, nil, fmt.Errorf("%w: IP version %d", errMalformed, version)
	}

	if len(b) < 1 {
		return AddressEntry{}, nil, errMalformed
	}
	bits := int(b[0])
	b = b[1:]
	prefix := netip.PrefixFrom(addr, bits)
	if bits > addr.BitLen() {
		return AddressEntry{}, nil, fmt.Errorf("%w: prefix %d over %d-bit address", errMalformed, bits, addr.BitLen())
	}
	return AddressEntry{RequestID: id, Prefix: prefix}, b, nil
}

// EncodeAddresses encodes a list of address groups, the value of both the
// ADDRESS_ASSIGN and ADDRESS_REQUEST capsules.
func EncodeAddresses(entries []AddressEntry) []byte {
	var out []byte
	for _, e := range entries {
		out = appendAddress(out, e)
	}
	return out
}

// ParseAddresses decodes an ADDRESS_ASSIGN or ADDRESS_REQUEST capsule value.
func ParseAddresses(value []byte) ([]AddressEntry, error) {
	var entries []AddressEntry
	for len(value) > 0 {
		e, rest, err := consumeAddress(value)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
		value = rest
	}
	return entries, nil
}

// RouteEntry is one advertised route (RFC 9484 §4.3): a closed address range and
// an IP protocol, where protocol 0 means all.
type RouteEntry struct {
	Start    netip.Addr
	End      netip.Addr
	Protocol uint8
}

func appendRoute(dst []byte, r RouteEntry) []byte {
	if r.Start.Is4() {
		dst = append(dst, 4)
		s, e := r.Start.As4(), r.End.As4()
		dst = append(dst, s[:]...)
		dst = append(dst, e[:]...)
	} else {
		dst = append(dst, 6)
		s, e := r.Start.As16(), r.End.As16()
		dst = append(dst, s[:]...)
		dst = append(dst, e[:]...)
	}
	return append(dst, r.Protocol)
}

func consumeRoute(b []byte) (RouteEntry, []byte, error) {
	if len(b) < 1 {
		return RouteEntry{}, nil, errMalformed
	}
	version := b[0]
	b = b[1:]

	var start, end netip.Addr
	switch version {
	case 4:
		if len(b) < 8 {
			return RouteEntry{}, nil, errMalformed
		}
		start = netip.AddrFrom4([4]byte(b[:4]))
		end = netip.AddrFrom4([4]byte(b[4:8]))
		b = b[8:]
	case 6:
		if len(b) < 32 {
			return RouteEntry{}, nil, errMalformed
		}
		start = netip.AddrFrom16([16]byte(b[:16]))
		end = netip.AddrFrom16([16]byte(b[16:32]))
		b = b[32:]
	default:
		return RouteEntry{}, nil, fmt.Errorf("%w: IP version %d", errMalformed, version)
	}

	if len(b) < 1 {
		return RouteEntry{}, nil, errMalformed
	}
	proto := b[0]
	return RouteEntry{Start: start, End: end, Protocol: proto}, b[1:], nil
}

// EncodeRoutes encodes the value of a ROUTE_ADVERTISEMENT capsule.
func EncodeRoutes(routes []RouteEntry) []byte {
	var out []byte
	for _, r := range routes {
		out = appendRoute(out, r)
	}
	return out
}

// ParseRoutes decodes a ROUTE_ADVERTISEMENT capsule value.
func ParseRoutes(value []byte) ([]RouteEntry, error) {
	var routes []RouteEntry
	for len(value) > 0 {
		r, rest, err := consumeRoute(value)
		if err != nil {
			return nil, err
		}
		routes = append(routes, r)
		value = rest
	}
	return routes, nil
}
