package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const (
	happyEyeballsDelay       = 250 * time.Millisecond
	happyEyeballsMaxParallel = 3
)

// resolveHappyEyeballsTargets resolves each hostname once and skips failed
// additional DNS lookups as long as at least one candidate remains. Unlike
// address hopping, a race selects one path for the lifetime of the QUIC session.
func resolveHappyEyeballsTargets(ctx context.Context, config node.Hysteria2, preferred *net.UDPAddr) ([]*net.UDPAddr, error) {
	var ipv4, ipv6 []*net.UDPAddr
	var lookupErr error
	resolved := make(map[string]*netapi.IPs)
	seen := make(map[string]bool)
	add := func(addr *net.UDPAddr) {
		if seen[addr.String()] {
			return
		}
		seen[addr.String()] = true
		if addr.IP.To4() != nil {
			ipv4 = append(ipv4, addr)
		} else {
			ipv6 = append(ipv6, addr)
		}
	}
	for _, value := range append([]string{config.Host}, config.HopAddresses...) {
		addr, ports, err := parseServerAddress(value)
		if err != nil {
			return nil, err
		}
		port := addr.Port()
		if port == 0 {
			port = 443
		}
		// Large hopping ranges must not create thousands of QUIC handshakes.
		// Sample one port per resolved IP for each configured address entry.
		if ports != nil {
			values := ports.Ports()
			port = values[rand.IntN(len(values))]
		}
		if _, ok := addr.(netapi.IPAddress); ok {
			remote, err := resolveHopAddress(ctx, addr)
			if err != nil {
				return nil, err
			}
			remote.Port = int(port)
			add(remote)
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(addr.Hostname(), "."))
		ips := resolved[key]
		if ips == nil {
			ips, err = netapi.ResolverIP(ctx, addr.Hostname())
			if err != nil {
				lookupErr = errors.Join(lookupErr, fmt.Errorf("resolve %q: %w", value, err))
				continue
			}
			if ips.Len() == 0 {
				lookupErr = errors.Join(lookupErr, fmt.Errorf("resolve %q: no IP addresses", value))
				continue
			}
			resolved[key] = ips
		}
		for ip := range ips.Iter() {
			add(&net.UDPAddr{IP: ip, Port: int(port)})
		}
	}
	var targets []*net.UDPAddr
	if netapi.GetContext(ctx).ConnOptions().Resolver().Mode() == netapi.ResolverModePreferIPv4 {
		targets = dialer.Interleave(ipv4, ipv6)
	} else {
		targets = dialer.Interleave(ipv6, ipv4)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("hysteria2 has no resolved addresses: %w", lookupErr)
	}
	if preferred != nil {
		for i, target := range targets {
			if target.String() == preferred.String() {
				copy(targets[1:i+1], targets[:i])
				targets[0] = target
				break
			}
		}
	}
	return targets, nil
}

type happyEyeballsResult[T io.Closer] struct {
	conn   T
	remote *net.UDPAddr
	err    error
}

// raceUDPAddresses uses authenticated-session success, not UDP socket creation,
// to choose a winner. Each attempt owns its own socket and QUIC transport.
// The unbuffered results channel ensures that losing successful sessions are
// closed after the winner cancels the race.
func raceUDPAddresses[T io.Closer](ctx context.Context, targets []*net.UDPAddr, dial func(context.Context, *net.UDPAddr) (T, error)) (T, *net.UDPAddr, error) {
	var zero T
	if len(targets) == 0 {
		return zero, nil, errors.New("hysteria2 happy eyeballs: no targets")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan happyEyeballsResult[T])
	start := func(target *net.UDPAddr) {
		go func() {
			conn, err := dial(ctx, target)
			result := happyEyeballsResult[T]{conn: conn, remote: target, err: err}
			select {
			case results <- result:
			case <-ctx.Done():
				if err == nil {
					_ = conn.Close()
				}
			}
		}()
	}
	start(targets[0])
	next, active := 1, 1
	ticker := time.NewTicker(happyEyeballsDelay)
	defer ticker.Stop()
	var dialErr error
	for active > 0 {
		select {
		case <-ctx.Done():
			return zero, nil, errors.Join(dialErr, ctx.Err())
		case <-ticker.C:
			if next < len(targets) && active < happyEyeballsMaxParallel {
				start(targets[next])
				next++
				active++
			}
		case result := <-results:
			active--
			if result.err == nil {
				if err := ctx.Err(); err != nil {
					_ = result.conn.Close()
					return zero, nil, err
				}
				return result.conn, result.remote, nil
			}
			dialErr = errors.Join(dialErr, fmt.Errorf("%s: %w", result.remote, result.err))
			if next < len(targets) {
				start(targets[next])
				next++
				active++
			}
		}
	}
	return zero, nil, fmt.Errorf("hysteria2 happy eyeballs: all addresses failed: %w", dialErr)
}
