package peerrendezvous

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// ResolveCoordinators lists at most one UDP address per IP family, IPv6 first.
// Lookups and tunnels share this order, so two peers that can use the first
// address choose the same family.
func ResolveCoordinators(ctx context.Context, address string) ([]netip.AddrPort, error) {
	a, err := netapi.ParseAddress("udp", address)
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	if resolved, ok := a.(netapi.IPAddress); ok {
		ips = []netip.Addr{resolved.AddrPort().Addr()}
	} else {
		found, err := netapi.Bootstrap().LookupIP(ctx, a.Hostname())
		if err != nil {
			return nil, err
		}
		for _, family := range [][]net.IP{found.AAAA, found.A} {
			if len(family) != 0 {
				ip, _ := netip.AddrFromSlice(family[0])
				ips = append(ips, ip)
			}
		}
	}
	var out []netip.AddrPort
	for _, ip := range ips {
		ip = ip.Unmap()
		if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.Zone() != "" ||
			slices.ContainsFunc(out, func(c netip.AddrPort) bool { return c.Addr().BitLen() == ip.BitLen() }) {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip, a.Port()))
	}
	if a.Port() == 0 || len(out) == 0 {
		return nil, errors.New("peer discovery requires a reachable unicast address")
	}
	return out, nil
}

// LookupAny asks every coordinator address at once and returns the first
// answer. A host without one IP family still gets an answer from the other.
func LookupAny(ctx context.Context, coordinators []netip.AddrPort, key [32]byte) (LookupResult, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type answer struct {
		result LookupResult
		err    error
	}
	answers := make(chan answer, len(coordinators))
	for _, coordinator := range coordinators {
		go func() {
			result, err := Lookup(ctx, coordinator, key)
			answers <- answer{result, err}
		}()
	}
	err := errors.New("peer discovery lookup: no coordinator address")
	for range coordinators {
		a := <-answers
		if a.err == nil {
			return a.result, nil
		}
		err = a.err
	}
	return LookupResult{}, err
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
