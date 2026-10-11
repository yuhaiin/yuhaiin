package softether

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"
)

// A learning bridge (IEEE 802.1D) that forwards Ethernet frames between
// sessions by destination MAC, with an ageing MAC table, broadcast/multicast
// flood, and ARP handling. Testable entirely in memory with no sockets.

const (
	// DefaultAgeTime is how long a MAC entry lives without being refreshed.
	DefaultAgeTime = 5 * time.Minute

	// MaxMACEntries is the bridge's ageing-table capacity.
	MaxMACEntries = 65536

	// EtherTypeARP is the EtherType field value for ARP.
	EtherTypeARP = 0x0806

	// EtherTypeIPv4 is the EtherType field value for IPv4.
	EtherTypeIPv4 = 0x0800

	// EtherTypeIPv6 is the EtherType field value for IPv6.
	EtherTypeIPv6 = 0x86DD

	// MaxFrameSize is the maximum Ethernet frame size (including header).
	MaxFrameSize = 1514
)

var (
	ErrMACTableFull = errors.New("softether: MAC table full")
	ErrNoPort       = errors.New("softether: no such port")
	ErrFrameTooLong = errors.New("softether: frame too long")
)

// PortID identifies a session on the bridge.
type PortID uint32

// MACAddr is a 6-byte Ethernet MAC address.
type MACAddr [6]byte

func (m MACAddr) String() string {
	return net.HardwareAddr(m[:]).String()
}

// macEntry is one row in the ageing MAC table.
type macEntry struct {
	port    PortID
	updated time.Time
}

// Bridge is a learning Ethernet switch.
type Bridge struct {
	mu       sync.RWMutex
	ageTime  time.Duration
	table    map[MACAddr]macEntry
	ports    map[PortID]struct{}
	nextPort PortID
}

// NewBridge creates a learning bridge with the given MAC-ageing timeout.
func NewBridge(ageTime time.Duration) *Bridge {
	return &Bridge{
		ageTime: ageTime,
		table:   make(map[MACAddr]macEntry),
		ports:   make(map[PortID]struct{}),
	}
}

// NewPort allocates a new port on the bridge and returns its ID.
func (b *Bridge) NewPort() PortID {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextPort++
	p := b.nextPort
	b.ports[p] = struct{}{}
	return p
}

// RemovePort removes a port and its MAC entries from the bridge.
func (b *Bridge) RemovePort(p PortID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.ports, p)
	for mac, entry := range b.table {
		if entry.port == p {
			delete(b.table, mac)
		}
	}
}

// Learn records that mac is reachable through port p.
func (b *Bridge) Learn(mac MACAddr, p PortID) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.ports[p]; !ok {
		return ErrNoPort
	}
	if len(b.table) >= MaxMACEntries {
		// Try to age out stale entries.
		b.evictLocked()
		if len(b.table) >= MaxMACEntries {
			return ErrMACTableFull
		}
	}
	b.table[mac] = macEntry{port: p, updated: time.Now()}
	return nil
}

// Lookup returns the port that mac was last seen on, or -1 if unknown.
func (b *Bridge) Lookup(mac MACAddr) PortID {
	b.mu.RLock()
	defer b.mu.RUnlock()
	entry, ok := b.table[mac]
	if !ok {
		return 0
	}
	if time.Since(entry.updated) > b.ageTime {
		return 0 // stale
	}
	return entry.port
}

// IsMulticast reports whether mac is a multicast or broadcast address.
func IsMulticast(mac MACAddr) bool {
	return mac[0]&0x01 != 0
}

// IsBroadcast reports whether mac is the Ethernet broadcast address.
func IsBroadcast(mac MACAddr) bool {
	return mac == MACAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

// ParseMAC parses a 6-byte MAC address from a frame's source or destination
// field. Returns the zero value on short input.
func ParseMAC(b []byte) MACAddr {
	var m MACAddr
	if len(b) < 6 {
		return m
	}
	copy(m[:], b[:6])
	return m
}

// ethFrame holds the relevant parts of an Ethernet frame for forwarding
// decisions: destination MAC, source MAC, EtherType, and payload.
type ethFrame struct {
	Dst  MACAddr
	Src  MACAddr
	Type uint16 // EtherType
	Body []byte
}

// ParseFrame parses an Ethernet frame (14-byte header + payload).
func ParseFrame(pkt []byte) (ethFrame, bool) {
	if len(pkt) < 14 {
		return ethFrame{}, false
	}
	return ethFrame{
		Dst:  ParseMAC(pkt[0:6]),
		Src:  ParseMAC(pkt[6:12]),
		Type: binary.BigEndian.Uint16(pkt[12:14]),
		Body: pkt[14:],
	}, true
}

// ForwardResult describes how the bridge should forward a frame.
type ForwardResult struct {
	// Destinations is the set of ports the frame should be forwarded to.
	// If nil, the frame should be flooded to all ports except the source.
	Destinations []PortID
	// ExcludeSource, if true, means the frame should not be sent back to
	// the source port (always true for unicast; true for flood).
	ExcludeSource bool
}

// Forward decides how to forward an incoming frame from port src.
func (b *Bridge) Forward(frame ethFrame, src PortID) ForwardResult {
	// Learn the source MAC. A failure here (unknown port, or a full table that
	// would not evict) is deliberately not fatal: forwarding still works, it
	// just floods instead of unicasting, which is what a real switch does.
	_ = b.Learn(frame.Src, src)

	// Broadcast/multicast: flood to all ports except the source.
	if IsMulticast(frame.Dst) {
		return ForwardResult{ExcludeSource: true} // nil Destinations = flood
	}

	// Unicast: look up the destination port.
	if dst := b.Lookup(frame.Dst); dst != 0 {
		return ForwardResult{Destinations: []PortID{dst}, ExcludeSource: true}
	}

	// Unknown unicast: flood.
	return ForwardResult{ExcludeSource: true}
}

// FloodPorts returns all bridge ports except exclude.
func (b *Bridge) FloodPorts(exclude PortID) []PortID {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var out []PortID
	for p := range b.ports {
		if p != exclude {
			out = append(out, p)
		}
	}
	return out
}

// evictLocked removes stale entries from the MAC table. Caller must hold b.mu.
func (b *Bridge) evictLocked() {
	now := time.Now()
	for mac, entry := range b.table {
		if now.Sub(entry.updated) > b.ageTime {
			delete(b.table, mac)
		}
	}
}

// TableLen returns the current number of MAC entries.
func (b *Bridge) TableLen() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.table)
}

// arpReply builds a minimal ARP reply for a given target protocol address.
// It constructs a complete Ethernet+ARP frame that the caller can write
// directly to a TAP device.
func arpReply(request []byte, ourMAC MACAddr, ourIP netip.Addr) ([]byte, bool) {
	if len(request) < 42 { // 14 (eth) + 28 (ARP)
		return nil, false
	}
	// Parse the ARP body (after 14-byte Ethernet header).
	arp := request[14:]
	if len(arp) < 28 {
		return nil, false
	}
	// Only respond to ARP requests (opcode 1).
	op := binary.BigEndian.Uint16(arp[6:8])
	if op != 1 {
		return nil, false
	}
	// Only respond for our IP.
	tpa := netip.AddrFrom4([4]byte(arp[24:28]))
	if tpa != ourIP {
		return nil, false
	}

	srcHW := arp[8:14]  // sender hardware addr
	dstHW := arp[18:24] // target hardware addr (all zeros in request)
	srcPA := arp[14:18] // sender protocol addr

	out := make([]byte, 42)
	copy(out[0:6], srcHW)      // dst in reply = src in request
	copy(out[6:12], ourMAC[:]) // src in reply = our MAC
	binary.BigEndian.PutUint16(out[12:14], EtherTypeARP)
	binary.BigEndian.PutUint16(out[14:16], 1)      // htype = Ethernet
	binary.BigEndian.PutUint16(out[16:18], 0x0800) // ptype = IPv4
	out[18] = 6                                    // hlen
	out[19] = 4                                    // plen
	binary.BigEndian.PutUint16(out[20:22], 2)      // op = reply
	copy(out[22:28], ourMAC[:])                    // sender MAC
	copy(out[28:32], ourIP.AsSlice())              // sender IP
	copy(out[32:38], dstHW)                        // target MAC
	copy(out[38:42], srcPA)                        // target IP

	return out, true
}

// uint16ToBytes is a helper matching binary.BigEndian.PutUint16.
var _ = binary.BigEndian.PutUint16

// init ensures the math import is used by IsMulticast.
func init() { _ = math.MaxUint16 }
