package globalprotect

// GlobalProtect's ESP activation and keying layout follow xen0bit/veepin,
// internal/gp at 810e017596c0b5b55bc0da563929bde13a6b201d (MIT).
// See ESP_THIRD_PARTY_LICENSE. The data codec implements RFC 4303 CBC/HMAC.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

type espKey struct {
	Bits  int    `xml:"bits"`
	Value string `xml:"val"`
}
type espConfig struct {
	Mode   string `xml:"ipsec-mode"`
	Port   int    `xml:"udp-port"`
	Enc    string `xml:"enc-algo"`
	Auth   string `xml:"hmac-algo"`
	OutSPI string `xml:"c2s-spi"`
	InSPI  string `xml:"s2c-spi"`
	OutKey espKey `xml:"ekey-c2s"`
	InKey  espKey `xml:"ekey-s2c"`
	OutMAC espKey `xml:"akey-c2s"`
	InMAC  espKey `xml:"akey-s2c"`
}

type espSA struct {
	outSPI, inSPI uint32
	out, in       cipher.Block
	outMAC, inMAC []byte
	digest        func() hash.Hash
	tagLen        int
	mu            sync.Mutex
	seq, top      uint32
	seen          uint64
}

var errESPInvalid = errors.New("globalprotect: invalid or replayed ESP packet")

func newESPSA(cfg espConfig) (*espSA, error) {
	if cfg.Mode != "esp-tunnel" {
		return nil, errors.New("globalprotect: unsupported ESP mode")
	}
	encLen := 0
	switch cfg.Enc {
	case "aes-128-cbc":
		encLen = 16
	case "aes-256-cbc":
		encLen = 32
	default:
		return nil, errors.New("globalprotect: unsupported ESP cipher")
	}
	var digest func() hash.Hash
	var macLen, tagLen int
	switch cfg.Auth {
	case "sha1":
		digest, macLen, tagLen = sha1.New, 20, 12
	case "sha256":
		digest, macLen, tagLen = sha256.New, 32, 16
	default:
		return nil, errors.New("globalprotect: unsupported ESP HMAC")
	}
	parse := func(k espKey, n int) ([]byte, error) {
		raw, err := hex.DecodeString(strings.TrimSpace(k.Value))
		if err != nil || len(raw) != n || k.Bits != n*8 {
			return nil, errors.New("globalprotect: invalid ESP key")
		}
		return raw, nil
	}
	outKey, err := parse(cfg.OutKey, encLen)
	if err != nil {
		return nil, err
	}
	inKey, err := parse(cfg.InKey, encLen)
	if err != nil {
		return nil, err
	}
	outMAC, err := parse(cfg.OutMAC, macLen)
	if err != nil {
		return nil, err
	}
	inMAC, err := parse(cfg.InMAC, macLen)
	if err != nil {
		return nil, err
	}
	parseSPI := func(s string) (uint32, error) {
		n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
		if err != nil || n < 256 {
			return 0, errors.New("globalprotect: invalid ESP SPI")
		}
		return uint32(n), nil
	}
	outSPI, err := parseSPI(cfg.OutSPI)
	if err != nil {
		return nil, err
	}
	inSPI, err := parseSPI(cfg.InSPI)
	if err != nil {
		return nil, err
	}
	out, err := aes.NewCipher(outKey)
	if err != nil {
		return nil, err
	}
	in, err := aes.NewCipher(inKey)
	if err != nil {
		return nil, err
	}
	return &espSA{outSPI: outSPI, inSPI: inSPI, out: out, in: in, outMAC: outMAC, inMAC: inMAC, digest: digest, tagLen: tagLen}, nil
}

func (s *espSA) seal(ip []byte) ([]byte, error) {
	if len(ip) == 0 || ip[0]>>4 != 4 && ip[0]>>4 != 6 {
		return nil, errESPInvalid
	}
	s.mu.Lock()
	if s.seq == 0xffffffff {
		s.mu.Unlock()
		return nil, errors.New("globalprotect: ESP sequence exhausted")
	}
	s.seq++
	seq := s.seq
	s.mu.Unlock()
	pad := (aes.BlockSize - (len(ip)+2)%aes.BlockSize) % aes.BlockSize
	plain := make([]byte, len(ip)+pad+2)
	copy(plain, ip)
	for i := range pad {
		plain[len(ip)+i] = byte(i + 1)
	}
	plain[len(plain)-2] = byte(pad)
	plain[len(plain)-1] = 4
	if ip[0]>>4 == 6 {
		plain[len(plain)-1] = 41
	}
	out := make([]byte, 8+aes.BlockSize+len(plain)+s.tagLen)
	binary.BigEndian.PutUint32(out[:4], s.outSPI)
	binary.BigEndian.PutUint32(out[4:8], seq)
	iv := out[8:24]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(s.out, iv).CryptBlocks(out[24:len(out)-s.tagLen], plain)
	mac := hmac.New(s.digest, s.outMAC)
	_, _ = mac.Write(out[:len(out)-s.tagLen])
	copy(out[len(out)-s.tagLen:], mac.Sum(nil)[:s.tagLen])
	return out, nil
}
func (s *espSA) open(packet []byte) ([]byte, error) {
	if len(packet) < 24+aes.BlockSize+s.tagLen || (len(packet)-24-s.tagLen)%aes.BlockSize != 0 || binary.BigEndian.Uint32(packet[:4]) != s.inSPI {
		return nil, errESPInvalid
	}
	mac := hmac.New(s.digest, s.inMAC)
	_, _ = mac.Write(packet[:len(packet)-s.tagLen])
	if !hmac.Equal(packet[len(packet)-s.tagLen:], mac.Sum(nil)[:s.tagLen]) {
		return nil, errESPInvalid
	}
	plain := packet[24 : len(packet)-s.tagLen]
	cipher.NewCBCDecrypter(s.in, packet[8:24]).CryptBlocks(plain, plain)
	pad := int(plain[len(plain)-2])
	next := plain[len(plain)-1]
	if pad+2 > len(plain) || next != 4 && next != 41 {
		return nil, errESPInvalid
	}
	for i := range pad {
		if plain[len(plain)-2-pad+i] != byte(i+1) {
			return nil, errESPInvalid
		}
	}
	ip := plain[:len(plain)-pad-2]
	if len(ip) < 20 || next == 4 && ip[0]>>4 != 4 || next == 41 && (len(ip) < 40 || ip[0]>>4 != 6) {
		return nil, errESPInvalid
	}
	n := 0
	if next == 4 {
		n = int(binary.BigEndian.Uint16(ip[2:4]))
		if n < int(ip[0]&15)*4 || ip[0]&15 < 5 {
			return nil, errESPInvalid
		}
	} else {
		n = 40 + int(binary.BigEndian.Uint16(ip[4:6]))
	}
	if n > len(ip) {
		return nil, errESPInvalid
	}
	seq := binary.BigEndian.Uint32(packet[4:8])
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq == 0 || seq <= s.top && (s.top-seq >= 64 || s.seen&(uint64(1)<<(s.top-seq)) != 0) {
		return nil, errESPInvalid
	}
	if seq > s.top {
		if seq-s.top >= 64 {
			s.seen = 0
		} else {
			s.seen <<= seq - s.top
		}
		s.top = seq
		s.seen |= 1
	} else {
		s.seen |= uint64(1) << (s.top - seq)
	}
	return ip[:n], nil
}

type espTunnel struct {
	socket        net.PacketConn
	peer          *net.UDPAddr
	sa            *espSA
	local, remote netip.Addr
}

func (e *espTunnel) send(ip []byte) error {
	packet, err := e.sa.seal(ip)
	if err != nil {
		return err
	}
	n, err := e.socket.WriteTo(packet, e.peer)
	if err == nil && n != len(packet) {
		return errors.New("globalprotect: short ESP datagram")
	}
	return err
}
func (e *espTunnel) receive(buf []byte) ([]byte, error) {
	for {
		n, source, err := e.socket.ReadFrom(buf)
		if err != nil {
			return nil, err
		}
		addr, err := netapi.ParseSysAddr(source)
		if err != nil || addr.Port() != uint16(e.peer.Port) || addr.Hostname() != e.peer.IP.String() {
			continue
		}
		ip, err := e.sa.open(buf[:n])
		if err == nil {
			return ip, nil
		}
	}
}

func connectESP(ctx context.Context, c *control, cfg gatewayConfig, local netip.Addr) (*espTunnel, error) {
	sa, err := newESPSA(*cfg.IPSec)
	if err != nil {
		return nil, err
	}
	host := cfg.GatewayAddress
	if host == "" {
		host = c.gateway.Hostname()
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		ips, e := netapi.Bootstrap().LookupIP(ctx, host)
		if e != nil {
			return nil, e
		}
		ip, _ = netip.AddrFromSlice(ips.Rand())
	}
	if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return nil, errors.New("globalprotect: invalid ESP gateway IPv4 address")
	}
	port := cfg.IPSec.Port
	if port == 0 {
		port = 4501
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("globalprotect: invalid ESP UDP port")
	}
	peer := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port)))
	upstream := c.upstream
	if upstream == nil || register.IsZero(upstream) {
		upstream = direct.Default
	}
	socket, err := upstream.PacketConn(ctx, netapi.ParseIPAddr("udp", peer.IP, uint16(port)))
	if err != nil {
		return nil, err
	}
	e := &espTunnel{socket: socket, peer: peer, sa: sa, local: local, remote: ip}
	activated := false
	defer func() {
		if !activated {
			_ = socket.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
	defer stop()
	buf := make([]byte, 2048)
	for seq := range 3 {
		if err := e.send(activationPing(local, ip, uint16(seq+1))); err != nil {
			return nil, err
		}
		until := time.Now().Add(2 * time.Second)
		if deadline, ok := ctx.Deadline(); ok {
			until = minTime(until, deadline)
		}
		if err := socket.SetReadDeadline(until); err != nil {
			return nil, err
		}
		if _, err := e.receive(buf); err == nil {
			if !stop() || ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err := socket.SetReadDeadline(time.Time{}); err != nil {
				return nil, err
			}
			activated = true
			return e, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("globalprotect: ESP activation timed out")
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func activationPing(src, dst netip.Addr, seq uint16) []byte {
	p := make([]byte, 76)
	p[0] = 0x45
	p[8] = 64
	p[9] = 1
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	p[20] = 8
	binary.BigEndian.PutUint16(p[24:26], 0xa5a5)
	binary.BigEndian.PutUint16(p[26:28], seq)
	copy(p[28:], "monitor\x00\x00pan ha 0123456789:;<=>? !\"#$%&'()*+,-./")
	binary.BigEndian.PutUint16(p[22:24], checksum(p[20:]))
	return p
}
func checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
func isActivationPacket(p []byte) bool {
	return len(p) >= 44 && p[0]>>4 == 4 && p[9] == 1 && string(p[28:44]) == "monitor\x00\x00pan ha "
}

func (c *Client) receiveESP() {
	buf := make([]byte, 65535)
	for {
		ip, err := c.esp.receive(buf)
		if err != nil {
			if c.ctx.Err() == nil {
				c.fail(fmt.Errorf("globalprotect: ESP receive: %w", err))
			}
			return
		}
		c.lastDPD.Store(time.Now().UnixNano())
		if isActivationPacket(ip) {
			continue
		}
		if len(ip) > c.mtu {
			continue
		}
		c.touchActivity()
		if _, err := c.tunnel.Write([][]byte{ip}, 0); err != nil {
			if c.ctx.Err() != nil {
				return
			}
		}
	}
}
