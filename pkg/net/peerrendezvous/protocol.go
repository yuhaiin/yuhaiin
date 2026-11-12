// Package peerrendezvous exchanges UDP endpoints for direct WireGuard peers.
package peerrendezvous

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
)

const (
	messageSize = 96
	magic       = "YHP1"
	hello       = 1
	challenge   = 2
	confirm     = 3
	discovered  = 4
	lookupFlag  = 1
	localFlag   = 3
	localProbe  = 6
	localReply  = 7
	denied      = 5
	blocked     = 1
	kicked      = 2
)

// Role identifies one side of a pairing. Each token reserves two slots.
type Role byte

const (
	Dialer Role = iota
	Publisher
)

// Layout: magic, kind, role, flags, reserved byte, pair ID, nonce, body, HMAC.
// The fixed-size reply cannot amplify unauthenticated UDP traffic.
type message [messageSize]byte

func pairID(key [32]byte) [16]byte {
	return transport.PeerPairID(key)
}

func (m *message) id() [16]byte    { return [16]byte(m[8:24]) }
func (m *message) nonce() [16]byte { return [16]byte(m[24:40]) }
func (m *message) body() []byte    { return m[40:64] }
func (m *message) kind() byte      { return m[4] }
func (m *message) role() Role      { return Role(m[5]) }
func (m *message) lookup() bool    { return m[6] == lookupFlag }
func (m *message) localPath() bool { return m[6] == localFlag }
func (m *message) sign(key [32]byte) {
	mac := hmac.New(sha256.New, key[:])
	mac.Write(m[:64])
	mac.Sum(m[:64])
}

func (m *message) valid(key [32]byte) bool {
	mac := hmac.New(sha256.New, key[:])
	mac.Write(m[:64])
	var sum [sha256.Size]byte
	return hmac.Equal(m[64:], mac.Sum(sum[:0]))
}

func (m *message) headerOK(n int) bool {
	return n == messageSize && string(m[:4]) == magic && m.role() <= Publisher && m[7] == 0 &&
		(m[6] == 0 || m.lookup() && m.role() == Dialer || m.localPath())
}

func (m *message) setEndpoint(endpoint netip.AddrPort) {
	clear(m.body())
	if endpoint.IsValid() {
		binary.BigEndian.PutUint16(m.body(), endpoint.Port())
		ip := endpoint.Addr().As16()
		copy(m.body()[2:], ip[:])
	}
}

func (m *message) endpoint() netip.AddrPort {
	port := binary.BigEndian.Uint16(m.body())
	ip := netip.AddrFrom16([16]byte(m.body()[2:18])).Unmap()
	if port == 0 || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip, port)
}

func (m *message) denial() string {
	if m.body()[0] == blocked {
		return "blocked"
	}
	return "kicked"
}
