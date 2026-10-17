package l2tp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/tailscale/wireguard-go/tun"
)

// ethernetNetwork adds Ethernet framing and bounded ARP/NDP resolution to the
// shared IP stack. TCP, UDP, fragmentation and congestion control stay in it.
type ethernetNetwork struct {
	*wireguard.LightweightNetTun
	ctx       context.Context
	cancel    context.CancelFunc
	mac       [6]byte
	routes    []ethernetRoute
	frames    chan []byte
	mu        sync.Mutex
	neighbors map[netip.Addr]*ethernetNeighbor
	pending   int
	wg        sync.WaitGroup
	once      sync.Once
}
type ethernetRoute struct {
	prefix netip.Prefix
	router netip.Addr
}
type ethernetNeighbor struct {
	mac      [6]byte
	expires  time.Time
	next     time.Time
	attempts int
	packets  [][]byte
}

const neighborLimit = 256

func newEthernetNetwork(cfg Config) (*ethernetNetwork, error) {
	n := &ethernetNetwork{frames: make(chan []byte, 256), neighbors: make(map[netip.Addr]*ethernetNeighbor)}
	_, _ = rand.Read(n.mac[:])
	n.mac[0] = (n.mac[0] | 2) &^ 1
	var prefixes []netip.Prefix
	for _, pair := range []struct{ address, router string }{{cfg.Address, cfg.Router}, {cfg.IPv6Address, cfg.IPv6Router}} {
		if pair.address == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(pair.address)
		if err != nil {
			return nil, err
		}
		var router netip.Addr
		if pair.router != "" {
			router, err = netip.ParseAddr(pair.router)
			if err != nil {
				return nil, err
			}
		}
		prefixes = append(prefixes, prefix)
		n.routes = append(n.routes, ethernetRoute{prefix, router})
		if prefix.Addr().Is6() {
			a := [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, n.mac[0] ^ 2, n.mac[1], n.mac[2], 0xff, 0xfe, n.mac[3], n.mac[4], n.mac[5]}
			local := netip.PrefixFrom(netip.AddrFrom16(a), 64)
			prefixes = append(prefixes, local)
			n.routes = append(n.routes, ethernetRoute{prefix: local})
		}
	}
	var err error
	n.LightweightNetTun, err = wireguard.CreateLightweightNetTUN(prefixes, cfg.MTU)
	if err != nil {
		return nil, err
	}
	n.ctx, n.cancel = context.WithCancel(context.Background())
	n.wg.Go(n.transmit)
	n.wg.Go(n.retryNeighbors)
	return n, nil
}

func (n *ethernetNetwork) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if len(packets) == 0 || len(slab) < 2*tun.ReadPacketSpacing {
		return 0, tun.ErrTooManySegments
	}
	select {
	case <-n.ctx.Done():
		return 0, net.ErrClosed
	case frame := <-n.frames:
		dst := slab[tun.ReadPacketSpacing : len(slab)-tun.ReadPacketSpacing]
		if len(frame) > len(dst) {
			return 0, tun.ErrTooManySegments
		}
		packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: copy(dst, frame)}
		return 1, nil
	}
}
func (n *ethernetNetwork) Write(buffers [][]byte, offset int) (int, error) {
	for _, b := range buffers {
		if offset < 0 || offset > len(b) {
			return 0, io.ErrShortBuffer
		}
	}
	for i, b := range buffers {
		if n.ctx.Err() != nil {
			return i, net.ErrClosed
		}
		f := b[offset:]
		if len(f) < 14 || f[0]&1 == 0 && [6]byte(f[:6]) != n.mac {
			continue
		}
		switch binary.BigEndian.Uint16(f[12:14]) {
		case 0x0806:
			n.handleARP(f)
		case 0x86dd:
			if n.handleNDP(f) {
				continue
			}
			fallthrough
		case 0x0800:
			if _, err := n.LightweightNetTun.Write([][]byte{f[14:]}, 0); err != nil {
				return i, err
			}
		}
	}
	return len(buffers), nil
}
func (n *ethernetNetwork) Close() error {
	n.once.Do(func() {
		n.cancel()
		_ = n.LightweightNetTun.Close()
		n.wg.Wait()
		n.mu.Lock()
		clear(n.neighbors)
		n.pending = 0
		n.mu.Unlock()
		for {
			select {
			case <-n.frames:
			default:
				return
			}
		}
	})
	return nil
}
func (n *ethernetNetwork) queueFrame(dst [6]byte, proto uint16, packet []byte) {
	if n.ctx.Err() != nil {
		return
	}
	frame := make([]byte, 14+len(packet))
	copy(frame[:6], dst[:])
	copy(frame[6:12], n.mac[:])
	binary.BigEndian.PutUint16(frame[12:14], proto)
	copy(frame[14:], packet)
	// The protocol has one frame reader. Bounded overflow acts as link loss and
	// must never hold the IP receiver while it processes a neighbor response.
	select {
	case <-n.ctx.Done():
	case n.frames <- frame:
	default:
	}
}
func (n *ethernetNetwork) transmit() {
	mtu, _ := n.MTU()
	buf := make([]byte, mtu)
	for {
		size, err := n.ReadPacket(buf)
		if err != nil {
			n.cancel()
			return
		}
		packet := buf[:size]
		var dst netip.Addr
		if size >= 20 && packet[0]>>4 == 4 {
			dst = netip.AddrFrom4([4]byte(packet[16:20]))
		} else if size >= 40 && packet[0]>>4 == 6 {
			dst = netip.AddrFrom16([16]byte(packet[24:40]))
		} else {
			continue
		}
		if dst.IsMulticast() {
			var mac [6]byte
			if dst.Is4() {
				a := dst.As4()
				mac = [6]byte{1, 0, 0x5e, a[1] & 127, a[2], a[3]}
			} else {
				a := dst.As16()
				mac = [6]byte{0x33, 0x33, a[12], a[13], a[14], a[15]}
			}
			n.sendIP(mac, packet)
			continue
		}
		next := dst
		best := -1
		var fallback netip.Addr
		for _, route := range n.routes {
			if route.prefix.Addr().Is4() != dst.Is4() {
				continue
			}
			if route.router.IsValid() {
				fallback = route.router
			}
			if route.prefix.Contains(dst) && route.prefix.Bits() > best {
				best = route.prefix.Bits()
				next = dst
			}
		}
		if best < 0 && fallback.IsValid() {
			next = fallback
		}
		n.mu.Lock()
		now := time.Now()
		entry := n.neighbors[next]
		if entry != nil && entry.mac != ([6]byte{}) && now.Before(entry.expires) {
			mac := entry.mac
			n.mu.Unlock()
			n.sendIP(mac, packet)
			continue
		}
		if entry == nil {
			if len(n.neighbors) >= neighborLimit {
				n.mu.Unlock()
				continue
			}
			entry = &ethernetNeighbor{}
			n.neighbors[next] = entry
		}
		if n.pending < neighborLimit {
			entry.packets = append(entry.packets, append([]byte(nil), packet...))
			n.pending++
		}
		if entry.attempts == 0 {
			entry.attempts = 1
			entry.next = now.Add(time.Second)
			n.solicit(next)
		}
		n.mu.Unlock()
	}
}
func (n *ethernetNetwork) sendIP(mac [6]byte, packet []byte) {
	proto := uint16(0x0800)
	if packet[0]>>4 == 6 {
		proto = 0x86dd
	}
	n.queueFrame(mac, proto, packet)
}
func (n *ethernetNetwork) retryNeighbors() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case now := <-ticker.C:
			n.mu.Lock()
			for ip, e := range n.neighbors {
				if len(e.packets) == 0 {
					if now.After(e.expires) {
						delete(n.neighbors, ip)
					}
					continue
				}
				if now.Before(e.next) {
					continue
				}
				if e.attempts >= 3 {
					n.pending -= len(e.packets)
					delete(n.neighbors, ip)
					continue
				}
				e.attempts++
				e.next = now.Add(time.Second)
				n.solicit(ip)
			}
			n.mu.Unlock()
		}
	}
}
func (n *ethernetNetwork) learn(ip netip.Addr, mac [6]byte) {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || mac == ([6]byte{}) || mac[0]&1 != 0 {
		return
	}
	n.mu.Lock()
	e := n.neighbors[ip]
	// Only replies to our own resolution requests can create cache entries.
	if e == nil {
		n.mu.Unlock()
		return
	}
	packets := e.packets
	n.pending -= len(packets)
	e.packets = nil
	e.mac = mac
	e.expires = time.Now().Add(time.Minute)
	e.attempts = 0
	n.mu.Unlock()
	for _, p := range packets {
		n.sendIP(mac, p)
	}
}
func (n *ethernetNetwork) local(ip netip.Addr) bool {
	for _, r := range n.routes {
		if r.prefix.Addr() == ip {
			return true
		}
	}
	return false
}
func (n *ethernetNetwork) source(target netip.Addr) netip.Addr {
	var source netip.Addr
	for _, r := range n.routes {
		ip := r.prefix.Addr()
		if ip.Is4() != target.Is4() {
			continue
		}
		source = ip
		if ip.IsLinkLocalUnicast() == target.IsLinkLocalUnicast() {
			return ip
		}
	}
	return source
}
