package peerrendezvous

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// ResolveCoordinator picks the same UDP address for lookups and tunnels.
func ResolveCoordinator(ctx context.Context, address string) (netip.AddrPort, error) {
	a, err := netapi.ParseAddress("udp", address)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var ip netip.Addr
	if resolved, ok := a.(netapi.IPAddress); ok {
		ip = resolved.AddrPort().Addr()
	} else {
		ips, err := netapi.Bootstrap().LookupIP(ctx, a.Hostname())
		if err != nil {
			return netip.AddrPort{}, err
		}
		ip, _ = netip.AddrFromSlice(ips.PreferAAAA())
	}
	ip = ip.Unmap()
	if a.Port() == 0 || !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.Zone() != "" {
		return netip.AddrPort{}, errors.New("peer discovery requires a reachable unicast address")
	}
	return netip.AddrPortFrom(ip, a.Port()), nil
}

type LookupResult struct {
	Endpoint netip.AddrPort
	Denial   string
}

// Lookup reads the publisher's current registration. A zero endpoint means
// the coordinator answered successfully and the publisher has no live lease.
func Lookup(ctx context.Context, coordinator netip.AddrPort, key [32]byte) (LookupResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	pc, err := dialer.DialUDPContext(ctx, coordinator)
	if err != nil {
		return LookupResult{}, err
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { _ = pc.Close() })
	defer stop()

	var request message
	copy(request[:4], magic)
	request[4], request[5], request[6] = hello, byte(Dialer), lookupFlag
	id := pairID(key)
	copy(request[8:24], id[:])
	rand.Read(request[24:40])
	request.sign(key)

	var buf [messageSize + 1]byte
	for ctx.Err() == nil {
		if err = pc.SetDeadline(time.Now().Add(600 * time.Millisecond)); err != nil {
			break
		}
		if _, err = pc.Write(request[:]); err != nil {
			break
		}
		n, err := pc.Read(buf[:])
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return LookupResult{}, err
		}
		response := message(buf[:messageSize])
		if !response.headerOK(n) || !response.lookup() || response.id() != id ||
			response.nonce() != request.nonce() || !response.valid(key) {
			continue
		}
		switch {
		case request.kind() == hello && response.kind() == challenge:
			request = response
			request[4] = confirm
			request.sign(key)
		case request.kind() == confirm && response.kind() == discovered:
			return LookupResult{Endpoint: response.endpoint()}, nil
		case request.kind() == confirm && response.kind() == denied:
			return LookupResult{Denial: response.denial()}, nil
		}
	}
	if ctx.Err() != nil {
		return LookupResult{}, ctx.Err()
	}
	return LookupResult{}, fmt.Errorf("peer discovery lookup: %w", err)
}
