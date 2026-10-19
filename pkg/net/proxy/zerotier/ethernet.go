//go:build (((linux && !android) || darwin) && (amd64 || arm64)) || (windows && amd64) || (android && arm64 && cgo)

package zerotier

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	zt "github.com/yuhaiin/zerotier-go"
)

const (
	etherIPv4 = 0x0800
	etherARP  = 0x0806
	etherIPv6 = 0x86dd
	broadcast = 0xffffffffffff
)

// etherBridge adapts raw IP packets to authenticated ZeroTier Ethernet frames.
// It owns a bounded neighbor cache and performs ARP and IPv6 NDP in userspace.
// The native core cannot discover IP -> MAC mappings on the application's behalf.
type etherBridge struct {
	cfg    zt.NetworkConfig
	send   func(zt.Frame)
	inject func([]byte) error

	mu        sync.Mutex
	neighbors map[netip.Addr]uint64
	pending   map[netip.Addr][][]byte
	requested map[netip.Addr]time.Time
}

func newEtherBridge(cfg zt.NetworkConfig, send func(zt.Frame), inject func([]byte) error) *etherBridge {
	return &etherBridge{
		cfg: cfg, send: send, inject: inject,
		neighbors: make(map[netip.Addr]uint64), pending: make(map[netip.Addr][][]byte),
		requested: make(map[netip.Addr]time.Time),
	}
}

func (b *etherBridge) emit(mac uint64, etherType uint16, data []byte) {
	b.send(zt.Frame{
		NetworkID: b.cfg.ID, SourceMAC: b.cfg.MAC,
		DestinationMAC: mac, EtherType: etherType, Data: data,
	})
}

func (b *etherBridge) local(ip netip.Addr) bool {
	for _, p := range b.cfg.Addresses {
		if p.Addr() == ip {
			return true
		}
	}
	return false
}

func (b *etherBridge) source(ip netip.Addr) netip.Addr {
	for _, p := range b.cfg.Addresses {
		if p.Addr().Is4() == ip.Is4() {
			return p.Addr()
		}
	}
	return netip.Addr{}
}

func (b *etherBridge) nextHop(dest netip.Addr) netip.Addr {
	b.mu.Lock()
	defer b.mu.Unlock()
	var best int = -1
	next := dest
	for _, route := range b.cfg.Routes {
		if route.Target.Contains(dest) && route.Target.Bits() > best && route.Via.IsValid() && !route.Via.IsUnspecified() {
			next, best = route.Via, route.Target.Bits()
		}
	}
	return next
}

// updateRoutes changes managed routes without disconnecting existing TCP/UDP sessions.
func (b *etherBridge) updateRoutes(routes []zt.Route) {
	b.mu.Lock()
	b.cfg.Routes = append([]zt.Route(nil), routes...)
	b.mu.Unlock()
}

func (b *etherBridge) outgoing(data []byte) {
	if len(data) < 1 {
		return
	}
	var dest netip.Addr
	var etherType uint16
	switch data[0] >> 4 {
	case 4:
		if len(data) < 20 || int(data[0]&15)*4 > len(data) {
			return
		}
		dest = netip.AddrFrom4([4]byte(data[16:20]))
		etherType = etherIPv4
	case 6:
		if len(data) < 40 {
			return
		}
		dest = netip.AddrFrom16([16]byte(data[24:40]))
		etherType = etherIPv6
	default:
		return
	}
	if dest.IsMulticast() {
		if dest.Is4() {
			ip := dest.As4()
			b.emit(0x01005e000000|uint64(ip[1]&0x7f)<<16|uint64(ip[2])<<8|uint64(ip[3]), etherType, append([]byte(nil), data...))
		} else {
			ip := dest.As16()
			b.emit(0x333300000000|uint64(binary.BigEndian.Uint32(ip[12:])), etherType, append([]byte(nil), data...))
		}
		return
	}
	if dest.Is4() && dest == netip.MustParseAddr("255.255.255.255") {
		b.emit(broadcast, etherType, append([]byte(nil), data...))
		return
	}
	next := b.nextHop(dest)
	b.mu.Lock()
	mac := b.neighbors[next]
	if mac != 0 {
		b.mu.Unlock()
		b.emit(mac, etherType, append([]byte(nil), data...))
		return
	}
	// Never allow an unresponsive peer or a hostile IP to grow memory forever.
	if _, exists := b.pending[next]; exists || len(b.pending) < 128 {
		if len(b.pending[next]) < 8 {
			b.pending[next] = append(b.pending[next], append([]byte(nil), data...))
		}
	} else {
		b.mu.Unlock()
		return // Do not grow the retry bookkeeping after the pending table is full.
	}
	last := b.requested[next]
	request := time.Since(last) >= time.Second
	if request {
		b.requested[next] = time.Now()
	}
	b.mu.Unlock()
	if request {
		if next.Is4() {
			b.requestARP(next)
		} else {
			b.requestNDP(next)
		}
	}
}

func (b *etherBridge) learn(ip netip.Addr, mac uint64) {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || mac == 0 || mac == broadcast || mac == b.cfg.MAC {
		return
	}
	b.mu.Lock()
	if len(b.neighbors) > 2048 {
		clear(b.neighbors)
	}
	b.neighbors[ip] = mac
	buffered := b.pending[ip]
	delete(b.pending, ip)
	delete(b.requested, ip)
	b.mu.Unlock()
	for _, p := range buffered {
		if len(p) == 0 {
			continue
		}
		if p[0]>>4 == 4 {
			b.emit(mac, etherIPv4, p)
		} else if p[0]>>4 == 6 {
			b.emit(mac, etherIPv6, p)
		}
	}
}

func (b *etherBridge) incoming(f zt.Frame) {
	if f.NetworkID != b.cfg.ID || f.SourceMAC == 0 || f.SourceMAC == b.cfg.MAC {
		return
	}
	switch f.EtherType {
	case etherARP:
		b.handleARP(f)
	case etherIPv4:
		if len(f.Data) < 20 || f.Data[0]>>4 != 4 {
			return
		}
		b.learn(netip.AddrFrom4([4]byte(f.Data[12:16])), f.SourceMAC)
		_ = b.inject(f.Data)
	case etherIPv6:
		if len(f.Data) < 40 || f.Data[0]>>4 != 6 {
			return
		}
		b.learn(netip.AddrFrom16([16]byte(f.Data[8:24])), f.SourceMAC)
		if b.handleNDP(f) {
			return
		}
		_ = b.inject(f.Data)
	}
}

func macBytes(mac uint64) [6]byte {
	return [6]byte{byte(mac >> 40), byte(mac >> 32), byte(mac >> 24), byte(mac >> 16), byte(mac >> 8), byte(mac)}
}
func fromMAC(b []byte) uint64 {
	if len(b) < 6 {
		return 0
	}
	var n uint64
	for _, v := range b[:6] {
		n = n<<8 | uint64(v)
	}
	return n
}

func (b *etherBridge) requestARP(target netip.Addr) {
	src := b.source(target)
	if !src.IsValid() {
		return
	}
	pkt := make([]byte, 28)
	binary.BigEndian.PutUint16(pkt[0:2], 1)
	binary.BigEndian.PutUint16(pkt[2:4], etherIPv4)
	pkt[4], pkt[5] = 6, 4
	binary.BigEndian.PutUint16(pkt[6:8], 1)
	mac := macBytes(b.cfg.MAC)
	copy(pkt[8:14], mac[:])
	src4, tgt4 := src.As4(), target.As4()
	copy(pkt[14:18], src4[:])
	copy(pkt[24:28], tgt4[:])
	b.emit(broadcast, etherARP, pkt)
}

func (b *etherBridge) handleARP(f zt.Frame) {
	p := f.Data
	if len(p) < 28 || binary.BigEndian.Uint16(p[0:2]) != 1 || binary.BigEndian.Uint16(p[2:4]) != etherIPv4 || p[4] != 6 || p[5] != 4 {
		return
	}
	op := binary.BigEndian.Uint16(p[6:8])
	if op != 1 && op != 2 {
		return
	}
	sender := netip.AddrFrom4([4]byte(p[14:18]))
	if fromMAC(p[8:14]) != f.SourceMAC {
		return // ZeroTier's authenticated sender MAC must match the ARP payload.
	}
	b.learn(sender, f.SourceMAC)
	target := netip.AddrFrom4([4]byte(p[24:28]))
	if op != 1 || !b.local(target) {
		return
	}
	reply := make([]byte, 28)
	copy(reply, p)
	binary.BigEndian.PutUint16(reply[6:8], 2)
	mac := macBytes(b.cfg.MAC)
	copy(reply[8:14], mac[:])
	target4 := target.As4()
	copy(reply[14:18], target4[:])
	copy(reply[18:24], p[8:14])
	copy(reply[24:28], p[14:18])
	b.emit(f.SourceMAC, etherARP, reply)
}

// IPv6 NDP uses solicited-node multicast rather than ARP.
func solicitedMAC(ip netip.Addr) uint64 {
	b := ip.As16()
	return 0x3333ff000000 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
}
func solicitedIP(ip netip.Addr) netip.Addr {
	out := [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff}
	src := ip.As16()
	copy(out[13:], src[13:])
	return netip.AddrFrom16(out)
}

func checksum16(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)&1 != 0 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func ipv6Checksum(src, dst netip.Addr, payload []byte) uint16 {
	sa, da := src.As16(), dst.As16()
	sum := checksum16(sa[:]) + checksum16(da[:])
	sum += uint32(len(payload)) + 58
	sum += checksum16(payload)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func ndpPacket(src, dst netip.Addr, typ byte, target netip.Addr, mac uint64, flags uint32) []byte {
	p := make([]byte, 40+32)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], 32)
	p[6], p[7] = 58, 255
	sa, da := src.As16(), dst.As16()
	copy(p[8:24], sa[:])
	copy(p[24:40], da[:])
	p[40] = typ
	binary.BigEndian.PutUint32(p[44:48], flags)
	ta := target.As16()
	copy(p[48:64], ta[:])
	if typ == 135 {
		p[64] = 1
	} else {
		p[64] = 2
	}
	p[65] = 1
	m := macBytes(mac)
	copy(p[66:72], m[:])
	binary.BigEndian.PutUint16(p[42:44], ipv6Checksum(src, dst, p[40:]))
	return p
}

func (b *etherBridge) requestNDP(target netip.Addr) {
	src := b.source(target)
	if !src.IsValid() {
		return
	}
	dest := solicitedIP(target)
	b.emit(solicitedMAC(target), etherIPv6, ndpPacket(src, dest, 135, target, b.cfg.MAC, 0))
}

// handleNDP handles neighbor discovery locally; the TCP/IP stack only sees IP.
func (b *etherBridge) handleNDP(f zt.Frame) bool {
	p := f.Data
	if len(p) < 64 || p[6] != 58 || p[7] != 255 {
		return false
	}
	typ := p[40]
	if typ != 135 && typ != 136 {
		return false
	}
	target := netip.AddrFrom16([16]byte(p[48:64]))
	if typ == 136 {
		b.learn(target, f.SourceMAC)
		return true
	}
	if !b.local(target) {
		return true
	}
	src := netip.AddrFrom16([16]byte(p[8:24]))
	dest := src
	destMAC := f.SourceMAC
	flags := uint32(0x60000000) // Solicited + Override
	if src.IsUnspecified() {
		dest = netip.MustParseAddr("ff02::1")
		destMAC = 0x333300000001
		flags = 0x20000000
	}
	b.emit(destMAC, etherIPv6, ndpPacket(target, dest, 136, target, b.cfg.MAC, flags))
	return true
}
