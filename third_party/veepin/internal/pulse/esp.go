package pulse

// The ESP-keying packet and the ESP data path.
//
// Pulse has no key exchange for its data path either: the server mints an SPI
// and a keying block and pushes them in a fixed-layout binary packet, and the
// client answers with its own. The two directions are therefore keyed
// independently, each end choosing what it will accept — which is a slightly
// better arrangement than GlobalProtect's, where the gateway chooses both.
//
// The layout below is openconnect's handle_esp_config_packet, with offsets
// counted from the start of the IF-T *payload* rather than the message, so
// every number here is 0x10 smaller than the one in its comments:
//
//	0x00  16 octets of zero
//	0x10  signature (0x21202400)
//	0x14  0x00000000
//	0x18  payload length (this packet's payload, in full)
//	0x1c  inner length (payload length less 0x1c)
//	0x20  0x01000000
//	0x24  SPI, LITTLE-endian — the one field in this protocol that is
//	0x28  secrets length (big-endian, always 0x40)
//	0x2a  encryption key immediately followed by the HMAC key, zero-padded
//	      out to the secrets length

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

// SecretsLen is the fixed size of one keying block. openconnect insists on
// exactly this value and says so in a comment; a server that sent another would
// be refused however well-formed the rest of the packet was.
const SecretsLen = 0x40

// Offsets within the ESP packet's payload.
const (
	espSigOffset     = 0x10
	espPayloadLenAt  = 0x18
	espInnerLenAt    = 0x1c
	espConstAt       = 0x20
	espSPIAt         = 0x24
	espSecretsLenAt  = 0x28
	espSecretsAt     = 0x2a
	espMinPayloadLen = espSecretsAt + SecretsLen
)

// espConst is the fixed word at 0x20. Its meaning is unknown; openconnect
// requires it and so does this.
const espConst = 0x01000000

// Keys is one direction's ESP keying material.
type Keys struct {
	SPI      uint32
	EncKey   []byte
	HMACKey  []byte
	Encr     uint16 // EncAES128CBC / EncAES256CBC
	Integrit uint16 // HMACSHA1 / HMACSHA256
}

// suite is a resolved cipher pair: the transform IDs internal/ikev2/esp speaks,
// and the key sizes the packet must carry.
type suite struct {
	encrID      uint16
	encrKeyBits int
	integID     uint16
	encKeyLen   int
	integKeyLen int
}

// resolveSuite maps the configuration attributes onto transform IDs.
//
// HMAC-MD5 is refused rather than implemented: it is one of the three values
// this protocol can name, no deployment needs it, and adding a broken MAC to
// the tree to be thorough would be the wrong trade.
func resolveSuite(encr, integ uint16) (suite, error) {
	var s suite
	switch encr {
	case EncAES128CBC:
		s.encrID, s.encrKeyBits, s.encKeyLen = payload.ENCR_AES_CBC, 128, 16
	case EncAES256CBC:
		s.encrID, s.encrKeyBits, s.encKeyLen = payload.ENCR_AES_CBC, 256, 32
	default:
		return suite{}, fmt.Errorf("pulse: unsupported ESP encryption %#04x", encr)
	}
	switch integ {
	case HMACSHA1:
		s.integID, s.integKeyLen = payload.AUTH_HMAC_SHA1_96, 20
	case HMACSHA256:
		s.integID, s.integKeyLen = payload.AUTH_HMAC_SHA2_256_128, 32
	case HMACMD5:
		return suite{}, errors.New("pulse: HMAC-MD5 is not implemented; ask the server for SHA1 or SHA256")
	default:
		return suite{}, fmt.Errorf("pulse: unsupported ESP HMAC %#04x", integ)
	}
	return s, nil
}

// GenerateKeys mints one direction's SPI and keys, sized for the chosen suite.
func GenerateKeys(encr, integ uint16) (*Keys, error) {
	s, err := resolveSuite(encr, integ)
	if err != nil {
		return nil, err
	}
	k := &Keys{Encr: encr, Integrit: integ}
	var spi [4]byte
	if _, err := rand.Read(spi[:]); err != nil {
		return nil, fmt.Errorf("pulse: generating an SPI: %w", err)
	}
	// RFC 4303 reserves SPIs below 256; setting the top bit avoids them without
	// a rejection loop.
	k.SPI = binary.BigEndian.Uint32(spi[:]) | 0x80000000

	k.EncKey = make([]byte, s.encKeyLen)
	k.HMACKey = make([]byte, s.integKeyLen)
	if _, err := rand.Read(k.EncKey); err != nil {
		return nil, fmt.Errorf("pulse: generating an ESP key: %w", err)
	}
	if _, err := rand.Read(k.HMACKey); err != nil {
		return nil, fmt.Errorf("pulse: generating an ESP key: %w", err)
	}
	return k, nil
}

// BuildESPPacket renders the server's keying packet: one block, its own.
func BuildESPPacket(k *Keys) ([]byte, error) {
	block, err := keyBlock(k)
	if err != nil {
		return nil, err
	}
	out := make([]byte, espSecretsAt+SecretsLen)
	putESPPreamble(out)
	copy(out[espSPIAt:], block)
	return out, nil
}

// BuildESPResponse renders the client's answer: its own keying block followed
// by a verbatim copy of the server's, which is how the server learns the client
// accepted the keys it sent.
func BuildESPResponse(mine *Keys, serverBlock []byte) ([]byte, error) {
	block, err := keyBlock(mine)
	if err != nil {
		return nil, err
	}
	if len(serverBlock) != len(block) {
		return nil, fmt.Errorf("pulse: server keying block is %d octets, want %d", len(serverBlock), len(block))
	}
	out := make([]byte, espSecretsAt+2*len(block))
	putESPPreamble(out)
	copy(out[espSPIAt:], block)
	copy(out[espSPIAt+len(block):], serverBlock)
	return out, nil
}

// keyBlock renders SPI | secrets length | keys, the unit both packets are built
// from. The SPI is little-endian; nothing else in this protocol is.
func keyBlock(k *Keys) ([]byte, error) {
	s, err := resolveSuite(k.Encr, k.Integrit)
	if err != nil {
		return nil, err
	}
	if len(k.EncKey) != s.encKeyLen || len(k.HMACKey) != s.integKeyLen {
		return nil, fmt.Errorf("pulse: keys are %d/%d octets, want %d/%d for the chosen suite",
			len(k.EncKey), len(k.HMACKey), s.encKeyLen, s.integKeyLen)
	}
	out := make([]byte, 6+SecretsLen)
	binary.LittleEndian.PutUint32(out[0:4], k.SPI)
	binary.BigEndian.PutUint16(out[4:6], SecretsLen)
	copy(out[6:], k.EncKey)
	copy(out[6+len(k.EncKey):], k.HMACKey)
	return out, nil
}

// putESPPreamble writes the fixed words and the two length fields, which are
// derived from the buffer's own size.
func putESPPreamble(out []byte) {
	binary.BigEndian.PutUint32(out[espSigOffset:], SigESP)
	binary.BigEndian.PutUint32(out[espPayloadLenAt:], uint32(len(out)))
	binary.BigEndian.PutUint32(out[espInnerLenAt:], uint32(len(out)-espInnerLenAt))
	binary.BigEndian.PutUint32(out[espConstAt:], espConst)
}

// ParseESPPacket decodes a keying packet's payload, returning the first keying
// block's SPI and keys and the raw block itself — which a client echoes back
// verbatim. encr and integ come from the configuration packet, which is what
// says how long the keys inside this one are.
func ParseESPPacket(p []byte, encr, integ uint16) (*Keys, []byte, error) {
	s, err := resolveSuite(encr, integ)
	if err != nil {
		return nil, nil, err
	}
	if len(p) < espMinPayloadLen {
		return nil, nil, errors.New("pulse: ESP keying packet too short")
	}
	if sig := binary.BigEndian.Uint32(p[espSigOffset:]); sig != SigESP {
		return nil, nil, fmt.Errorf("pulse: not an ESP keying packet (signature %#x)", sig)
	}
	if got := binary.BigEndian.Uint32(p[espPayloadLenAt:]); int(got) != len(p) {
		return nil, nil, fmt.Errorf("pulse: ESP payload length %d disagrees with the %d octets present", got, len(p))
	}
	if got := binary.BigEndian.Uint32(p[espInnerLenAt:]); int(got) != len(p)-espInnerLenAt {
		return nil, nil, errors.New("pulse: ESP inner length disagrees with the packet")
	}
	if binary.BigEndian.Uint32(p[espConstAt:]) != espConst {
		return nil, nil, errors.New("pulse: ESP keying packet is missing its constant")
	}
	if n := binary.BigEndian.Uint16(p[espSecretsLenAt:]); n != SecretsLen {
		return nil, nil, fmt.Errorf("pulse: secrets length is %#x, want %#x", n, SecretsLen)
	}
	if s.encKeyLen+s.integKeyLen > SecretsLen {
		return nil, nil, errors.New("pulse: the chosen suite needs more key material than the packet carries")
	}

	secrets := p[espSecretsAt : espSecretsAt+SecretsLen]
	k := &Keys{
		// Little-endian, deliberately. openconnect calls this insane and it is,
		// but it is what the wire carries.
		SPI:      binary.LittleEndian.Uint32(p[espSPIAt:]),
		EncKey:   append([]byte(nil), secrets[:s.encKeyLen]...),
		HMACKey:  append([]byte(nil), secrets[s.encKeyLen:s.encKeyLen+s.integKeyLen]...),
		Encr:     encr,
		Integrit: integ,
	}
	block := append([]byte(nil), p[espSPIAt:espSecretsAt+SecretsLen]...)
	return k, block, nil
}

// NewSA builds the ESP security association from the two directions' keys.
func NewSA(out, in *Keys) (*esp.SA, error) {
	so, err := resolveSuite(out.Encr, out.Integrit)
	if err != nil {
		return nil, err
	}
	si, err := resolveSuite(in.Encr, in.Integrit)
	if err != nil {
		return nil, err
	}
	return &esp.SA{
		SPIOut: out.SPI,
		SPIIn:  in.SPI,
		Out: esp.Transform{
			EncrID: so.encrID, EncrKeyLn: uint16(so.encrKeyBits), IntegID: so.integID,
			EncKey: out.EncKey, IntegKey: out.HMACKey,
		},
		In: esp.Transform{
			EncrID: si.encrID, EncrKeyLn: uint16(si.encrKeyBits), IntegID: si.integID,
			EncKey: in.EncKey, IntegKey: in.HMACKey,
		},
	}, nil
}

// Inbound drop sentinels, pre-built so the reject route allocates nothing.
var (
	errDummyPacket = errors.New("pulse: ESP dummy packet (next-header 59)")
	errBadInner    = errors.New("pulse: inner packet does not match its declared length")
)

// Tunnel adapts an ESP SA to dataplane.Tunnel.
type Tunnel struct {
	sa     *esp.SA
	inSPI  uint32
	routes []netip.Prefix
	peer   atomic.Pointer[net.UDPAddr]
}

// NewTunnel wraps an SA for the pump.
func NewTunnel(sa *esp.SA, inSPI uint32, routes []netip.Prefix, peer *net.UDPAddr) *Tunnel {
	t := &Tunnel{sa: sa, inSPI: inSPI, routes: routes}
	t.peer.Store(peer)
	return t
}

func (t *Tunnel) InboundKey() uint32     { return t.inSPI }
func (t *Tunnel) Routes() []netip.Prefix { return t.routes }
func (t *Tunnel) PeerAddr() *net.UDPAddr { return t.peer.Load() }

// SetPeerAddr repoints the return path at the address ESP actually arrives
// from, which is how a server follows a client whose NAT binding moves.
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

// EncapsulatePadded is Encapsulate with RFC 4303 section 2.7
// traffic-flow-confidentiality padding, implementing dataplane.PaddingTunnel.
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
	case 59:
		return nil, errDummyPacket
	case 4, 41:
		if inner = dataplane.TrimToIP(inner); inner == nil {
			return nil, errBadInner
		}
	}
	return inner, nil
}

func espNextHeader(ipPacket []byte) byte {
	if len(ipPacket) > 0 && ipPacket[0]>>4 == 6 {
		return 41
	}
	return 4
}
