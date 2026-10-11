package pulse

// The configuration packet: what the server pushes once authentication has
// finished, carrying the client's address, DNS, MTU, routes and the ESP
// parameters.
//
// It rides an IF-T/TLS Juniper/1 message and has a fixed preamble, a routing
// block, and then a chain of type-length-value attributes. The layout is not
// specified anywhere; the offsets and the length cross-checks below are exactly
// the ones openconnect's handle_main_config_packet enforces, because a packet
// that fails any of them is one it refuses outright.
//
//	0x00  0x0000000000000000 0000000000000000    16 octets of zero
//	0x10  signature (0x2c20f000)
//	0x14  0x00000000
//	0x18  payload length (the IF-T length less 0x10)
//	0x1c  0x2e00 | routing-block length
//	0x20  route count | 3 octets of zero
//	0x24  route entries, 0x10 octets each
//	 ...  attribute-element block length (4 octets)
//	 ...  0x03000000
//	 ...  attributes: type(2) | length(2) | value
//
// Those offsets are relative to the *payload*, which is where this package's
// codec works; openconnect's comments count from the start of the IF-T message,
// so every offset there is 0x10 larger than the one here.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Signature words at payload offset 0x10, telling the two configuration
// packets apart.
const (
	// SigConfig opens the main configuration packet. Servers from 9.1R14
	// onwards use 0x2e20f000 with a leading attribute block; veepin's server
	// emits the older, simpler form, which every client still accepts.
	SigConfig = 0x2c20f000
	// SigConfigR14 is that newer variant, accepted on parse.
	SigConfigR14 = 0x2e20f000
	// SigESP opens the ESP-keying packet.
	SigESP = 0x21202400
)

// Configuration attribute types.
const (
	AttrIPv4Address   = 0x0001
	AttrIPv4Netmask   = 0x0002
	AttrIPv4DNS       = 0x0003
	AttrIPv4WINS      = 0x0004
	AttrIPv6Address   = 0x0008 // 16 octets of address plus a prefix-length octet
	AttrIPv6DNS       = 0x000a
	AttrIPv6Include   = 0x000f
	AttrIPv6Exclude   = 0x0010
	AttrMTU           = 0x4005
	AttrSearchDomain  = 0x4006
	AttrGateway       = 0x400b
	AttrESPEncryption = 0x4010
	AttrESPHMAC       = 0x4011
	AttrESPLifeSecs   = 0x4012
	AttrESPLifeBytes  = 0x4013
	AttrESPReplay     = 0x4014
	AttrESPPort       = 0x4016
	AttrESPFallback   = 0x4017
	AttrESPOnly       = 0x401a
	AttrGateway6      = 0x401e
)

// ESP cipher and HMAC identifiers, as the 0x4010 and 0x4011 attributes carry
// them. These are Juniper's own numbering, not IANA's.
const (
	EncAES128CBC = 2
	EncAES256CBC = 5

	HMACMD5    = 1
	HMACSHA1   = 2
	HMACSHA256 = 3
)

// Route entry types in the routing block. The trailing 0x10 is the entry size.
const (
	routeInclude = 0x07000010
	routeExclude = 0xf1000010
)

// routeEntryLen is the fixed size of one routing entry: type(4) | 0x0000ffff |
// first address(4) | last address(4).
const routeEntryLen = 0x10

// Route is one split-tunnel network. The wire form is an inclusive address
// range rather than a prefix, which is why this keeps both ends.
type Route struct {
	Net     *net.IPNet
	Exclude bool
}

// Config is a decoded configuration packet.
type Config struct {
	Address net.IP
	Netmask net.IP
	DNS     []net.IP
	WINS    []net.IP
	MTU     int
	Domain  string
	Gateway net.IP
	Routes  []Route

	// ESP parameters. Port zero means the server offered no ESP data path.
	ESPPort       int
	ESPEncryption uint16
	ESPHMAC       uint16
	ESPLifeSecs   uint32
	ESPLifeBytes  uint32
	ESPFallback   uint32
	ESPReplay     uint32
}

const (
	cfgPreambleLen  = 0x24 // through the route count, before the first entry
	cfgSigOffset    = 0x10
	cfgPayloadLenAt = 0x18
	cfgRoutesAt     = 0x1c
)

// BuildConfig renders the main configuration packet's payload.
func BuildConfig(c Config) []byte {
	routes := buildRoutes(c.Routes)
	attrs := buildAttrs(c)

	// The attribute-element block: its own length, the fixed 0x03000000 word,
	// then the attributes.
	elems := make([]byte, 8+len(attrs))
	binary.BigEndian.PutUint32(elems[0:4], uint32(len(elems)))
	binary.BigEndian.PutUint32(elems[4:8], 0x03000000)
	copy(elems[8:], attrs)

	out := make([]byte, cfgPreambleLen+len(routes)+len(elems))
	binary.BigEndian.PutUint32(out[cfgSigOffset:], SigConfig)
	// The payload length openconnect cross-checks against the IF-T length.
	binary.BigEndian.PutUint32(out[cfgPayloadLenAt:], uint32(len(out)+HeaderLen-0x10))
	binary.BigEndian.PutUint16(out[cfgRoutesAt:], 0x2e00)
	binary.BigEndian.PutUint16(out[cfgRoutesAt+2:], uint16(len(routes)+8))
	out[0x20] = byte(len(c.Routes))
	copy(out[cfgPreambleLen:], routes)
	copy(out[cfgPreambleLen+len(routes):], elems)
	return out
}

// buildRoutes renders the routing entries. Each is a type word, a fixed
// 0x0000ffff, and the first and last addresses of an inclusive range — which is
// how this protocol spells a prefix.
func buildRoutes(routes []Route) []byte {
	out := make([]byte, 0, len(routes)*routeEntryLen)
	var e [routeEntryLen]byte
	for _, r := range routes {
		first, last, ok := rangeOf(r.Net)
		if !ok {
			continue
		}
		typ := uint32(routeInclude)
		if r.Exclude {
			typ = routeExclude
		}
		binary.BigEndian.PutUint32(e[0:4], typ)
		binary.BigEndian.PutUint32(e[4:8], 0x0000ffff)
		copy(e[8:12], first)
		copy(e[12:16], last)
		out = append(out, e[:]...)
	}
	return out
}

// rangeOf turns a network into the inclusive address range the wire format
// carries. A non-IPv4 network has no representation here and is skipped.
func rangeOf(n *net.IPNet) (first, last net.IP, ok bool) {
	if n == nil {
		return nil, nil, false
	}
	ip := n.IP.To4()
	if ip == nil || len(n.Mask) != net.IPv4len {
		return nil, nil, false
	}
	first = make(net.IP, net.IPv4len)
	last = make(net.IP, net.IPv4len)
	for i := range net.IPv4len {
		first[i] = ip[i] & n.Mask[i]
		last[i] = first[i] | ^n.Mask[i]
	}
	return first, last, true
}

// netOf is rangeOf's inverse: the network whose addresses run from first to
// last. The mask comes straight from the two ends, which is what openconnect
// does — a range that is not a prefix produces a mask that is not contiguous,
// and net.IPNet is honest about that rather than guessing.
func netOf(first, last []byte) *net.IPNet {
	mask := make(net.IPMask, net.IPv4len)
	for i := range net.IPv4len {
		mask[i] = ^(first[i] ^ last[i])
	}
	return &net.IPNet{IP: net.IPv4(first[0], first[1], first[2], first[3]).To4(), Mask: mask}
}

// buildAttrs renders the attribute chain. Only what was actually configured is
// sent: an absent attribute is unambiguous, where an empty one is not.
func buildAttrs(c Config) []byte {
	var out []byte
	add := func(typ uint16, v []byte) {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], typ)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(v)))
		out = append(out, hdr...)
		out = append(out, v...)
	}
	addIP := func(typ uint16, ip net.IP) {
		if v4 := ip.To4(); v4 != nil {
			add(typ, v4)
		}
	}
	addBE32 := func(typ uint16, v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		add(typ, b[:])
	}
	addBE16 := func(typ uint16, v uint16) {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], v)
		add(typ, b[:])
	}

	addIP(AttrIPv4Address, c.Address)
	addIP(AttrIPv4Netmask, net.IP(c.Netmask))
	for _, d := range c.DNS {
		addIP(AttrIPv4DNS, d)
	}
	for _, w := range c.WINS {
		addIP(AttrIPv4WINS, w)
	}
	if c.MTU > 0 {
		addBE32(AttrMTU, uint32(c.MTU))
	}
	if c.Domain != "" {
		add(AttrSearchDomain, []byte(c.Domain))
	}
	addIP(AttrGateway, c.Gateway)
	if c.ESPPort > 0 {
		addBE16(AttrESPEncryption, c.ESPEncryption)
		addBE16(AttrESPHMAC, c.ESPHMAC)
		addBE32(AttrESPLifeSecs, c.ESPLifeSecs)
		addBE32(AttrESPLifeBytes, c.ESPLifeBytes)
		addBE32(AttrESPReplay, c.ESPReplay)
		addBE16(AttrESPPort, uint16(c.ESPPort))
		addBE32(AttrESPFallback, c.ESPFallback)
	}
	return out
}

// ParseConfig decodes a main configuration packet's payload.
func ParseConfig(p []byte) (Config, error) {
	var c Config
	if len(p) < cfgPreambleLen+1 {
		return c, errors.New("pulse: configuration packet too short")
	}
	switch sig := binary.BigEndian.Uint32(p[cfgSigOffset:]); sig {
	case SigConfig, SigConfigR14:
	default:
		return c, fmt.Errorf("pulse: not a configuration packet (signature %#x)", sig)
	}

	// Walk any leading attribute blocks a 9.1R14-or-later server prepends,
	// then the routing block. The blocks are told apart by their marker word:
	// 0x2e00 opens the routes and is where the walk stops.
	off := cfgRoutesAt
	for {
		if len(p) < off+4 {
			return c, errors.New("pulse: truncated configuration block header")
		}
		marker := binary.BigEndian.Uint16(p[off:])
		blockLen := int(binary.BigEndian.Uint16(p[off+2:]))
		if marker == 0x2e00 {
			break
		}
		if marker != 0x2c00 {
			return c, fmt.Errorf("pulse: unknown configuration block %#04x", marker)
		}
		if blockLen < 4 || off+blockLen > len(p) {
			return c, errors.New("pulse: configuration block length out of range")
		}
		off += blockLen
	}

	routesLen := int(binary.BigEndian.Uint16(p[off+2:]))
	if len(p) < off+8 {
		return c, errors.New("pulse: truncated routing block")
	}
	count := int(p[off+4])
	// The routing block is a fixed eight-octet header plus one entry per route,
	// and the two must agree — the cross-check openconnect makes before it
	// trusts either number.
	if routesLen != count*routeEntryLen+8 || off+routesLen+4 > len(p) {
		return c, errors.New("pulse: routing block length disagrees with its route count")
	}
	entries := p[off+8 : off+routesLen]
	for len(entries) >= routeEntryLen {
		typ := binary.BigEndian.Uint32(entries[0:4])
		if binary.BigEndian.Uint32(entries[4:8]) != 0x0000ffff {
			return c, errors.New("pulse: malformed routing entry")
		}
		switch typ {
		case routeInclude:
			c.Routes = append(c.Routes, Route{Net: netOf(entries[8:12], entries[12:16])})
		case routeExclude:
			c.Routes = append(c.Routes, Route{Net: netOf(entries[8:12], entries[12:16]), Exclude: true})
		default:
			return c, fmt.Errorf("pulse: routing entry of unknown type %#08x", typ)
		}
		entries = entries[routeEntryLen:]
	}

	elems := p[off+routesLen:]
	if len(elems) < 8 {
		return c, errors.New("pulse: truncated attribute block")
	}
	elemLen := int(binary.BigEndian.Uint32(elems[0:4]))
	if elemLen < 8 || elemLen > len(elems) {
		return c, errors.New("pulse: attribute block length out of range")
	}
	if err := parseAttrs(elems[8:elemLen], &c); err != nil {
		return c, err
	}
	return c, nil
}

// parseAttrs walks the type-length-value chain. An attribute this
// implementation does not recognise is skipped rather than refused: a real
// server sends a dozen the client has no use for, and openconnect does the
// same.
func parseAttrs(b []byte, c *Config) error {
	for len(b) > 0 {
		if len(b) < 4 {
			return errors.New("pulse: truncated attribute header")
		}
		typ := binary.BigEndian.Uint16(b[0:2])
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if n+4 > len(b) {
			return fmt.Errorf("pulse: attribute %#04x overruns the block", typ)
		}
		v := b[4 : 4+n]
		b = b[4+n:]

		switch typ {
		case AttrIPv4Address:
			if len(v) == net.IPv4len {
				c.Address = net.IPv4(v[0], v[1], v[2], v[3]).To4()
			}
		case AttrIPv4Netmask:
			if len(v) == net.IPv4len {
				c.Netmask = net.IPv4(v[0], v[1], v[2], v[3]).To4()
			}
		case AttrIPv4DNS:
			if len(v) == net.IPv4len {
				c.DNS = append(c.DNS, net.IPv4(v[0], v[1], v[2], v[3]).To4())
			}
		case AttrIPv4WINS:
			if len(v) == net.IPv4len {
				c.WINS = append(c.WINS, net.IPv4(v[0], v[1], v[2], v[3]).To4())
			}
		case AttrMTU:
			if len(v) == 4 {
				c.MTU = int(binary.BigEndian.Uint32(v))
			}
		case AttrSearchDomain:
			// A real server NUL-terminates this; the terminator is not part of
			// the name.
			for len(v) > 0 && v[len(v)-1] == 0 {
				v = v[:len(v)-1]
			}
			c.Domain = string(v)
		case AttrGateway:
			if len(v) == net.IPv4len {
				c.Gateway = net.IPv4(v[0], v[1], v[2], v[3]).To4()
			}
		case AttrESPEncryption:
			if len(v) == 2 {
				c.ESPEncryption = binary.BigEndian.Uint16(v)
			}
		case AttrESPHMAC:
			if len(v) == 2 {
				c.ESPHMAC = binary.BigEndian.Uint16(v)
			}
		case AttrESPPort:
			if len(v) == 2 {
				c.ESPPort = int(binary.BigEndian.Uint16(v))
			}
		case AttrESPLifeSecs:
			if len(v) == 4 {
				c.ESPLifeSecs = binary.BigEndian.Uint32(v)
			}
		case AttrESPLifeBytes:
			if len(v) == 4 {
				c.ESPLifeBytes = binary.BigEndian.Uint32(v)
			}
		case AttrESPReplay:
			if len(v) == 4 {
				c.ESPReplay = binary.BigEndian.Uint32(v)
			}
		case AttrESPFallback:
			if len(v) == 4 {
				c.ESPFallback = binary.BigEndian.Uint32(v)
			}
		}
	}
	return nil
}
