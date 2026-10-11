package gp

// The ESP data path: the keys from the configuration document, plugged into the
// RFC 4303 codec every IPsec protocol here already shares.
//
// GlobalProtect runs ordinary ESP over UDP — no RFC 3948 non-ESP marker, no IKE,
// no rekey. The gateway generated both SPIs and all four keys and put them in the
// XML; this file turns those into an esp.SA and adapts it to dataplane.Tunnel.
//
// The one piece of protocol here that is not ESP is the activation exchange. A
// gateway does not consider the ESP path live until the client has sent it a
// recognisable packet, so the client sends ICMP echo requests carrying a fixed
// 16-octet marker and waits for anything back. Until that answer arrives the
// client cannot tell an ESP path that works from one a middlebox is dropping,
// which is exactly what the fallback to the SSL tunnel exists for.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
	"github.com/xen0bit/veepin/internal/ikev2/payload"
)

// The algorithm names this implementation offers, most preferred first. They are
// the wire spellings, which is what goes in the getconfig form and comes back in
// the document.
//
// Only CBC suites appear. Real gateways answer with aes-128-cbc essentially
// always, and the GCM spellings a client may advertise have no defined way to
// carry the four-octet salt RFC 4106 requires — the document has one key element
// per direction and no salt. Rather than invent a convention that would
// interoperate with nothing, GCM is refused with a clear error.
var (
	supportedEncAlgos  = []string{"aes-256-cbc", "aes-128-cbc"}
	supportedHMACAlgos = []string{"sha256", "sha1"}
)

// espSuite is one resolved algorithm pair: the transform IDs internal/ikev2/esp
// speaks, and the key sizes the document must carry.
type espSuite struct {
	encrID      uint16
	encrKeyBits int
	integID     uint16
	encKeyLen   int
	integKeyLen int
}

// resolveSuite maps the document's algorithm names onto transform IDs.
func resolveSuite(encAlgo, hmacAlgo string) (espSuite, error) {
	var s espSuite
	switch encAlgo {
	case "aes-128-cbc":
		s.encrID, s.encrKeyBits, s.encKeyLen = payload.ENCR_AES_CBC, 128, 16
	case "aes-256-cbc":
		s.encrID, s.encrKeyBits, s.encKeyLen = payload.ENCR_AES_CBC, 256, 32
	case "":
		return espSuite{}, errors.New("gp: the gateway named no ESP encryption algorithm")
	default:
		return espSuite{}, fmt.Errorf("gp: unsupported ESP encryption algorithm %q", encAlgo)
	}
	switch hmacAlgo {
	case "sha1":
		s.integID, s.integKeyLen = payload.AUTH_HMAC_SHA1_96, 20
	case "sha256":
		s.integID, s.integKeyLen = payload.AUTH_HMAC_SHA2_256_128, 32
	case "":
		return espSuite{}, errors.New("gp: the gateway named no ESP authentication algorithm")
	default:
		return espSuite{}, fmt.Errorf("gp: unsupported ESP authentication algorithm %q", hmacAlgo)
	}
	return s, nil
}

// SelectESPAlgos picks the algorithms to use from what a client offered. An
// offer this implementation cannot speak is skipped rather than refused, so a
// client advertising GCM ahead of CBC still gets CBC. Empty offers mean the
// client said nothing, which is answered with the defaults.
func SelectESPAlgos(encOffer, hmacOffer []string) (encAlgo, hmacAlgo string) {
	pick := func(offer, supported []string) string {
		for _, o := range offer {
			for _, s := range supported {
				if o == s {
					return s
				}
			}
		}
		// The last supported entry is the conservative one (aes-128-cbc, sha1),
		// which is what a gateway that cannot agree falls back to.
		return supported[len(supported)-1]
	}
	return pick(encOffer, supportedEncAlgos), pick(hmacOffer, supportedHMACAlgos)
}

// GenerateESP mints a fresh keying block: two SPIs and four keys sized for the
// chosen algorithms. It is the gateway's job — the client contributes nothing to
// the keys, which is the protocol's design.
func GenerateESP(encAlgo, hmacAlgo string) (*ESPConfig, error) {
	suite, err := resolveSuite(encAlgo, hmacAlgo)
	if err != nil {
		return nil, err
	}
	e := &ESPConfig{
		UDPPort:  DefaultESPPort,
		EncAlgo:  encAlgo,
		HMACAlgo: hmacAlgo,
	}
	if e.C2SSPI, err = randomSPI(); err != nil {
		return nil, err
	}
	if e.S2CSPI, err = randomSPI(); err != nil {
		return nil, err
	}
	for _, k := range []struct {
		dst *[]byte
		n   int
	}{
		{&e.EKeyC2S, suite.encKeyLen},
		{&e.AKeyC2S, suite.integKeyLen},
		{&e.EKeyS2C, suite.encKeyLen},
		{&e.AKeyS2C, suite.integKeyLen},
	} {
		b := make([]byte, k.n)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("gp: generating ESP keys: %w", err)
		}
		*k.dst = b
	}
	return e, nil
}

// randomSPI draws an SPI. Values below 256 are reserved by RFC 4303, so the top
// bit is set rather than rejecting and retrying.
func randomSPI() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("gp: generating an SPI: %w", err)
	}
	return binary.BigEndian.Uint32(b[:]) | 0x80000000, nil
}

// NewSA builds the ESP security association for one role. client selects whose
// point of view the c2s/s2c naming is read from: a client sends on c2s, a gateway
// sends on s2c.
func (e *ESPConfig) NewSA(client bool) (*esp.SA, error) {
	suite, err := resolveSuite(e.EncAlgo, e.HMACAlgo)
	if err != nil {
		return nil, err
	}
	if err := e.checkKeys(suite); err != nil {
		return nil, err
	}
	c2s := esp.Transform{
		EncrID:    suite.encrID,
		EncrKeyLn: uint16(suite.encrKeyBits),
		IntegID:   suite.integID,
		EncKey:    e.EKeyC2S,
		IntegKey:  e.AKeyC2S,
	}
	s2c := esp.Transform{
		EncrID:    suite.encrID,
		EncrKeyLn: uint16(suite.encrKeyBits),
		IntegID:   suite.integID,
		EncKey:    e.EKeyS2C,
		IntegKey:  e.AKeyS2C,
	}
	if client {
		return &esp.SA{SPIOut: e.C2SSPI, SPIIn: e.S2CSPI, Out: c2s, In: s2c}, nil
	}
	return &esp.SA{SPIOut: e.S2CSPI, SPIIn: e.C2SSPI, Out: s2c, In: c2s}, nil
}

// checkKeys rejects a keying block whose key sizes do not match the algorithms it
// names. A short key would otherwise be silently accepted by the cipher's own
// length check or, worse, used at the wrong strength.
func (e *ESPConfig) checkKeys(s espSuite) error {
	for _, k := range []struct {
		name string
		key  []byte
		want int
	}{
		{"ekey-c2s", e.EKeyC2S, s.encKeyLen},
		{"ekey-s2c", e.EKeyS2C, s.encKeyLen},
		{"akey-c2s", e.AKeyC2S, s.integKeyLen},
		{"akey-s2c", e.AKeyS2C, s.integKeyLen},
	} {
		if len(k.key) != k.want {
			return fmt.Errorf("gp: %s is %d octets, want %d for %s/%s",
				k.name, len(k.key), k.want, e.EncAlgo, e.HMACAlgo)
		}
	}
	if e.C2SSPI == 0 || e.S2CSPI == 0 {
		return errors.New("gp: the keying block carries a zero SPI")
	}
	return nil
}

// Inbound drop sentinels, pre-built so the reject route allocates nothing however
// much stray traffic arrives.
var (
	errDummyPacket = errors.New("gp: ESP dummy packet (next-header 59)")
	errBadInner    = errors.New("gp: inner packet does not match its declared length")
)

// Tunnel adapts an ESP SA to dataplane.Tunnel, so the ESP data path is the same
// pump every other datagram protocol here uses.
type Tunnel struct {
	sa     *esp.SA
	inSPI  uint32
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]
}

// NewTunnel wraps an SA for the pump. routes are the inner destinations this
// tunnel carries; peer is where ESP is sent.
func NewTunnel(sa *esp.SA, inSPI uint32, routes []netip.Prefix, peer *net.UDPAddr) *Tunnel {
	t := &Tunnel{sa: sa, inSPI: inSPI, routes: routes}
	t.peer.Store(peer)
	return t
}

func (t *Tunnel) InboundKey() uint32     { return t.inSPI }
func (t *Tunnel) Routes() []netip.Prefix { return t.routes }
func (t *Tunnel) PeerAddr() *net.UDPAddr { return t.peer.Load() }

// SetPeerAddr repoints the return path at the address ESP actually arrives from,
// which is how the gateway follows a client behind a NAT that rebinds. It stores
// only on a real change, to keep the inbound hot loop free of needless writes.
func (t *Tunnel) SetPeerAddr(a *net.UDPAddr) {
	if a == nil {
		return
	}
	if cur := t.peer.Load(); cur != nil && cur.Port == a.Port && cur.IP.Equal(a.IP) {
		return
	}
	t.peer.Store(a)
}

// Encapsulate protects one inner IP packet as ESP in tunnel mode.
func (t *Tunnel) Encapsulate(ipPacket []byte) ([]byte, error) {
	return t.sa.Encapsulate(ipPacket, espNextHeader(ipPacket))
}

// EncapsulatePadded is Encapsulate with RFC 4303 §2.7 traffic-flow-confidentiality
// padding, implementing dataplane.PaddingTunnel.
func (t *Tunnel) EncapsulatePadded(ipPacket []byte, minInner int) ([]byte, error) {
	return t.sa.EncapsulatePadded(ipPacket, espNextHeader(ipPacket), minInner)
}

// AppendEncapsulated is EncapsulatePadded into the pump's buffer, implementing
// dataplane.AppendTunnel.
func (t *Tunnel) AppendEncapsulated(dst, ipPacket []byte, minInner int) ([]byte, error) {
	return t.sa.AppendEncapsulated(dst, ipPacket, espNextHeader(ipPacket), minInner)
}

// Decapsulate opens an ESP packet, trimming any TFC padding the sender added.
func (t *Tunnel) Decapsulate(espPkt []byte) ([]byte, error) {
	inner, nextHeader, err := t.sa.Decapsulate(espPkt)
	if err != nil {
		return nil, err
	}
	switch nextHeader {
	case 59: // NoNextHeader: a pure filler packet with nothing inside.
		return nil, errDummyPacket
	case 4, 41:
		if inner = dataplane.TrimToIP(inner); inner == nil {
			return nil, errBadInner
		}
	}
	return inner, nil
}

// espNextHeader names the inner packet's family for the ESP trailer.
func espNextHeader(ipPacket []byte) byte {
	if len(ipPacket) > 0 && ipPacket[0]>>4 == 6 {
		return 41
	}
	return 4
}

// The activation exchange.
//
// magicPing is the 16-octet marker a GlobalProtect client puts in the ICMP echo
// requests that wake the gateway's ESP path up. It is exactly 16 octets; the
// reference client sends more bytes after it, and the reference gateway checks
// only these, so that is what is checked here too.
var magicPing = []byte("monitor\x00\x00pan ha ")

// pingFiller pads the activation ping out past its marker, so the packet is a
// plausible echo request rather than a suspiciously short one.
var pingFiller = []byte("0123456789:;<=>? !\"#$%&'()*+,-./")

// activationPings is how many activation packets a client sends before deciding
// the ESP path is not usable. Three is the reference client's count: enough that
// a single lost datagram does not condemn the path, few enough that a blocked one
// falls back promptly.
const activationPings = 3

const (
	protoICMP        = 1
	icmpEchoRequest  = 8
	icmpEchoReply    = 0
	ipv4HeaderLen    = 20
	icmpEchoHeadLen  = 8
	icmpEchoMinTotal = ipv4HeaderLen + icmpEchoHeadLen + 16
)

// BuildActivationPing renders one ICMP echo request carrying the marker, from the
// client's inner address to the gateway address the configuration named. seq
// distinguishes the probes in a burst.
func BuildActivationPing(src, dst net.IP, seq uint16) ([]byte, error) {
	s, d := src.To4(), dst.To4()
	if s == nil || d == nil {
		return nil, errors.New("gp: the activation ping needs IPv4 addresses")
	}
	payloadLen := len(magicPing) + len(pingFiller)
	pkt := make([]byte, ipv4HeaderLen+icmpEchoHeadLen+payloadLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], seq) // identification
	pkt[8] = 64                               // TTL
	pkt[9] = protoICMP
	copy(pkt[12:16], s)
	copy(pkt[16:20], d)
	putIPv4Checksum(pkt[:ipv4HeaderLen])

	icmp := pkt[ipv4HeaderLen:]
	icmp[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(icmp[4:6], 0xa5a5) // identifier
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[icmpEchoHeadLen:], magicPing)
	copy(icmp[icmpEchoHeadLen+len(magicPing):], pingFiller)
	putICMPChecksum(icmp)
	return pkt, nil
}

// IsActivationPing reports whether an inner packet is one of the marker echo
// requests. A gateway answers these itself rather than routing them: they are
// addressed to its own outer address, which is not a destination the tunnel is
// meant to carry traffic to.
func IsActivationPing(pkt []byte) bool {
	if len(pkt) < icmpEchoMinTotal || pkt[0]>>4 != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(pkt) < ihl+icmpEchoHeadLen+len(magicPing) {
		return false
	}
	// A packet shorter than its own header says is truncated, and a marker found
	// inside one is not evidence of anything. Inbound packets reach here through
	// dataplane.TrimToIP, which trims to exactly this length, so a mismatch means
	// the packet is malformed rather than merely padded.
	if total := int(binary.BigEndian.Uint16(pkt[2:4])); total < ihl+icmpEchoHeadLen+len(magicPing) || len(pkt) < total {
		return false
	}
	if pkt[9] != protoICMP {
		return false
	}
	icmp := pkt[ihl:]
	if icmp[0] != icmpEchoRequest {
		return false
	}
	body := icmp[icmpEchoHeadLen:]
	return len(body) >= len(magicPing) && string(body[:len(magicPing)]) == string(magicPing)
}

// ActivationReply turns an activation ping into its echo reply, which is what
// tells the client the ESP path carries traffic in both directions. It returns a
// fresh packet; req is not modified.
func ActivationReply(req []byte) ([]byte, error) {
	if !IsActivationPing(req) {
		return nil, errors.New("gp: not an activation ping")
	}
	ihl := int(req[0]&0x0f) * 4
	reply := make([]byte, len(req))
	copy(reply, req)

	// Swap the addresses so the reply goes back where the request came from.
	copy(reply[12:16], req[16:20])
	copy(reply[16:20], req[12:16])
	putIPv4Checksum(reply[:ihl])

	icmp := reply[ihl:]
	icmp[0] = icmpEchoReply
	putICMPChecksum(icmp)
	return reply, nil
}

// putIPv4Checksum recomputes the header checksum in place.
func putIPv4Checksum(hdr []byte) {
	hdr[10], hdr[11] = 0, 0
	binary.BigEndian.PutUint16(hdr[10:12], onesComplement(hdr))
}

// putICMPChecksum recomputes the ICMP checksum in place. ICMP's checksum covers
// the message alone — there is no pseudo-header, unlike ICMPv6.
func putICMPChecksum(icmp []byte) {
	icmp[2], icmp[3] = 0, 0
	binary.BigEndian.PutUint16(icmp[2:4], onesComplement(icmp))
}

// onesComplement is the internet checksum of b.
func onesComplement(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
