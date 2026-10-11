package dataplane

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// AddrPool hands out internal IPv4 addresses from a CIDR to connecting clients
// and reclaims them on disconnect. The network and broadcast addresses, plus a
// configurable gateway address, are reserved.
type AddrPool struct {
	mu      sync.Mutex
	network *net.IPNet
	gateway uint32
	base    uint32 // first assignable host (inclusive)
	last    uint32 // last assignable host (inclusive)
	used    map[uint32]bool
}

// NewAddrPool creates a pool over cidr (e.g. "10.10.10.0/24"). The first usable
// host is reserved as the gateway (the server's tunnel-side address).
func NewAddrPool(cidr string) (*AddrPool, net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}
	if ipnet.IP.To4() == nil {
		return nil, nil, fmt.Errorf("dataplane: only IPv4 pools supported")
	}
	netStart := binary.BigEndian.Uint32(ipnet.IP.To4())
	ones, bits := ipnet.Mask.Size()
	size := uint32(1) << uint(bits-ones)
	if size < 4 {
		return nil, nil, fmt.Errorf("dataplane: pool %s too small", cidr)
	}
	gateway := netStart + 1     // .1 is the server
	base := netStart + 2        // first client host
	last := netStart + size - 2 // last host before broadcast

	p := &AddrPool{
		network: ipnet,
		gateway: gateway,
		base:    base,
		last:    last,
		used:    make(map[uint32]bool),
	}
	return p, u32IP(gateway), nil
}

// Network returns the pool's CIDR network.
func (p *AddrPool) Network() *net.IPNet { return p.network }

// Gateway returns the server's tunnel-side address (the pool gateway).
func (p *AddrPool) Gateway() net.IP { return u32IP(p.gateway) }

// Netmask returns the pool netmask as a 4-byte IP.
func (p *AddrPool) Netmask() net.IP {
	return net.IP(p.network.Mask)
}

// Allocate returns the lowest free address, or an error if the pool is
// exhausted. Scanning from the base makes released addresses immediately
// reusable and keeps assignments compact.
func (p *AddrPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for cand := p.base; cand <= p.last; cand++ {
		if !p.used[cand] {
			p.used[cand] = true
			return u32IP(cand), nil
		}
	}
	return nil, fmt.Errorf("dataplane: address pool exhausted")
}

// Release returns an address to the pool.
func (p *AddrPool) Release(ip net.IP) {
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, binary.BigEndian.Uint32(v4))
}

func u32IP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}
