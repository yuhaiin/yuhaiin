package dataplane

import (
	"fmt"
	"net/netip"
	"sync"
)

// AddrPool6 hands out internal IPv6 addresses from a prefix to connecting
// clients and reclaims them on disconnect. It is the v6 sibling of AddrPool; a
// separate type because IPv6 has no broadcast address and a v6 prefix's host
// space is far too large to enumerate into a uint32 range — addresses are walked
// lazily with netip.Addr.Next instead.
//
// The first host (::1 within the prefix) is reserved as the gateway (the
// server's tunnel-side address); assignment begins at the next address.
type AddrPool6 struct {
	mu      sync.Mutex
	prefix  netip.Prefix
	gateway netip.Addr
	next    netip.Addr // lowest address not yet tried
	used    map[netip.Addr]bool
}

// NewAddrPool6 creates a pool over cidr (e.g. "fd00:10:10::/64"). The prefix must
// be IPv6 and leave at least two host addresses (gateway + one client). It
// returns the pool and the reserved gateway address.
func NewAddrPool6(cidr string) (*AddrPool6, netip.Addr, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	prefix = prefix.Masked()
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return nil, netip.Addr{}, fmt.Errorf("dataplane: pool %s is not IPv6", cidr)
	}
	if prefix.Bits() > 126 {
		return nil, netip.Addr{}, fmt.Errorf("dataplane: pool %s too small", cidr)
	}
	network := prefix.Addr()  // ::0 within the prefix
	gateway := network.Next() // ::1 is the server
	base := gateway.Next()    // first client host
	p := &AddrPool6{
		prefix:  prefix,
		gateway: gateway,
		next:    base,
		used:    make(map[netip.Addr]bool),
	}
	return p, gateway, nil
}

// Prefix returns the pool's CIDR prefix.
func (p *AddrPool6) Prefix() netip.Prefix { return p.prefix }

// Bits returns the prefix length assigned to clients (the CP prefix octet).
func (p *AddrPool6) Bits() int { return p.prefix.Bits() }

// Gateway returns the server's tunnel-side IPv6 address (the pool gateway).
func (p *AddrPool6) Gateway() netip.Addr { return p.gateway }

// Allocate returns the lowest free address, or an error if the pool is
// exhausted. Like AddrPool it scans from a low-water mark and reuses released
// addresses, keeping assignments compact without materialising the whole range.
func (p *AddrPool6) Allocate() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for cand := p.next; p.prefix.Contains(cand); cand = cand.Next() {
		if !p.used[cand] {
			p.used[cand] = true
			p.next = cand.Next()
			return cand, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("dataplane: IPv6 address pool exhausted")
}

// Release returns an address to the pool and lowers the scan mark so it is
// reused ahead of fresh addresses.
func (p *AddrPool6) Release(ip netip.Addr) {
	if !ip.IsValid() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.used[ip] {
		return
	}
	delete(p.used, ip)
	if ip.Less(p.next) {
		p.next = ip
	}
}
