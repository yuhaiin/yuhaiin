package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const (
	// RFC 8305 recommends 50 ms to give the preferred DNS family a chance
	// to arrive and 250 ms between connection attempts.
	happyEyeballsResolutionDelay = 50 * time.Millisecond
	happyEyeballsDelay           = 250 * time.Millisecond
	happyEyeballsMaxParallel     = 3
)

type happyEyeballsBatch struct {
	addrs []*net.UDPAddr
	err   error
}

// happyEyeballsAnswers starts independent A and AAAA queries immediately.
// Responses are streamed to the connection racer as they arrive. Unlike a
// snapshot resolver, a slow or broken address family cannot hold up the other.
//
// For entries with a port list/range, one port is sampled per race. When the
// previously successful endpoint's port belongs to that set it is reused, so
// the racer can recognise and prioritise that endpoint again.
func happyEyeballsAnswers(ctx context.Context, config node.Hysteria2, preferred *net.UDPAddr) (<-chan happyEyeballsBatch, error) {
	type dnsEntry struct {
		name  string
		ports []uint16
	}
	hosts := make(map[string]*dnsEntry)
	var hostOrder []string
	var literals []*net.UDPAddr
	for _, value := range append([]string{config.Host}, config.HopAddresses...) {
		addr, ports, err := parseServerAddress(value)
		if err != nil {
			return nil, fmt.Errorf("hysteria2 address %q: %w", value, err)
		}
		port := addr.Port()
		if port == 0 {
			port = 443
		}
		// One port per entry per connection race; port-range hopping remains
		// available through the separate periodic hopping mode.
		if ports != nil {
			if preferred != nil && preferred.Port > 0 && preferred.Port <= 65535 && ports.contains(uint16(preferred.Port)) {
				port = uint16(preferred.Port)
			} else {
				port = ports.random(rand.IntN)
			}
		}
		if _, ok := addr.(netapi.IPAddress); ok {
			remote, err := resolveHopAddress(ctx, addr)
			if err != nil {
				return nil, err
			}
			remote.Port = int(port)
			literals = append(literals, remote)
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(addr.Hostname(), "."))
		entry := hosts[name]
		if entry == nil {
			entry = &dnsEntry{name: addr.Hostname()}
			hosts[name] = entry
			hostOrder = append(hostOrder, name)
		}
		entry.ports = append(entry.ports, port)
	}

	resolver := netapi.GetContext(ctx).ConnOptions().Resolver().Resolver()
	if resolver == nil {
		resolver = netapi.Bootstrap()
	}
	batches := make(chan happyEyeballsBatch, len(hostOrder)*2+1)
	var wg sync.WaitGroup
	for _, hostname := range hostOrder {
		entry := hosts[hostname]
		for _, mode := range []netapi.ResolverMode{netapi.ResolverModePreferIPv6, netapi.ResolverModePreferIPv4} {
			wg.Go(func() {
				ips, err := resolver.LookupIP(ctx, entry.name, func(opt *netapi.LookupIPOption) {
					opt.Mode = mode
				})
				batch := happyEyeballsBatch{err: err}
				if err == nil && ips != nil {
					var values []net.IP
					if mode == netapi.ResolverModePreferIPv4 {
						values = ips.A
					} else {
						values = ips.AAAA
					}
					for _, ip := range values {
						for _, port := range entry.ports {
							batch.addrs = append(batch.addrs, &net.UDPAddr{IP: ip, Port: int(port)})
						}
					}
				}
				select {
				case batches <- batch:
				case <-ctx.Done():
				}
			})
		}
	}
	if len(literals) != 0 {
		batches <- happyEyeballsBatch{addrs: literals}
	}
	go func() {
		wg.Wait()
		close(batches)
	}()
	return batches, nil
}

// happyEyeballsKey identifies an endpoint. IPv4 addresses are unmapped so
// 4-byte and 16-byte net.IP forms of the same address compare equal.
func happyEyeballsKey(addr *net.UDPAddr) netip.AddrPort {
	ap := addr.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

type happyEyeballsResult[T io.Closer] struct {
	conn   T
	remote *net.UDPAddr
	err    error
}

// raceHappyEyeballsv2 implements the RFC 8305 asynchronous DNS, first-family
// preference, interleaved attempts, and failure acceleration for QUIC.
// Success requires a complete Hysteria 2 authentication, not just a UDP socket.
func raceHappyEyeballsv2[T io.Closer](
	parent context.Context,
	batches <-chan happyEyeballsBatch,
	preferred *net.UDPAddr,
	preferIPv4 bool,
	dial func(context.Context, *net.UDPAddr) (T, error),
) (T, *net.UDPAddr, error) {
	var zero T
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	var first, second []*net.UDPAddr
	// The previously successful endpoint is held aside instead of being
	// searched for in the queues on every pick. Keys are netip.AddrPort so
	// deduplication and matching do not format addresses as strings.
	var preferredKey netip.AddrPort
	if preferred != nil {
		preferredKey = happyEyeballsKey(preferred)
	}
	var preferredReady *net.UDPAddr
	seen := make(map[netip.AddrPort]struct{})
	results := make(chan happyEyeballsResult[T])
	source := batches
	var errAll error
	var active int
	var lastFamily = -1
	var launched bool
	var lastStart time.Time
	var graceUntil time.Time
	var accelerate bool

	familyOf := func(addr *net.UDPAddr) int {
		if (addr.IP.To4() != nil) == preferIPv4 {
			return 0
		}
		return 1
	}
	pending := func() int {
		n := len(first) + len(second)
		if preferredReady != nil {
			n++
		}
		return n
	}
	// The previously successful endpoint goes first; otherwise the preferred
	// address family leads and the two families are interleaved.
	choose := func() *net.UDPAddr {
		if addr := preferredReady; addr != nil {
			preferredReady = nil
			lastFamily = familyOf(addr)
			return addr
		}
		queue := &first
		family := 0
		if (lastFamily == 0 && len(second) != 0) || len(first) == 0 {
			queue = &second
			family = 1
		}
		if len(*queue) == 0 {
			return nil
		}
		result := (*queue)[0]
		(*queue)[0] = nil
		*queue = (*queue)[1:]
		lastFamily = family
		return result
	}
	start := func(addr *net.UDPAddr) {
		active++
		launched = true
		lastStart = time.Now()
		go func() {
			conn, err := dial(ctx, addr)
			r := happyEyeballsResult[T]{conn: conn, remote: addr, err: err}
			select {
			case results <- r:
			case <-ctx.Done():
				if err == nil {
					_ = conn.Close()
				}
			}
		}()
	}

	for {
		// A failed attempt immediately unlocks another candidate (RFC 8305
		// failure acceleration); ordinary attempts are staggered by 250ms.
		var wake <-chan time.Time
		if active < happyEyeballsMaxParallel && pending() != 0 {
			now := time.Now()
			wait := time.Duration(0)
			if !launched && preferredReady == nil && len(first) == 0 && len(second) != 0 && source != nil {
				if graceUntil.IsZero() {
					graceUntil = now.Add(happyEyeballsResolutionDelay)
				}
				wait = max(time.Duration(0), time.Until(graceUntil))
			} else if launched && !accelerate {
				wait = max(time.Duration(0), happyEyeballsDelay-time.Since(lastStart))
			}
			if wait == 0 {
				if addr := choose(); addr != nil {
					start(addr)
					accelerate = false
					continue
				}
			} else {
				wake = time.After(wait)
			}
		}
		if source == nil && active == 0 && pending() == 0 {
			if errAll == nil {
				errAll = errors.New("no usable DNS addresses")
			}
			return zero, nil, fmt.Errorf("hysteria2 happy eyeballs: all addresses failed: %w", errAll)
		}

		select {
		case <-ctx.Done():
			return zero, nil, errors.Join(errAll, ctx.Err())
		case <-wake:
			// Re-evaluate pending attempts and timers.
		case batch, ok := <-source:
			if !ok {
				source = nil
				continue
			}
			errAll = errors.Join(errAll, batch.err)
			for _, addr := range batch.addrs {
				key := happyEyeballsKey(addr)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				switch {
				case preferred != nil && key == preferredKey:
					preferredReady = addr
				case familyOf(addr) == 0:
					first = append(first, addr)
				default:
					second = append(second, addr)
				}
			}
		case result := <-results:
			active--
			if result.err == nil {
				if ctx.Err() != nil {
					_ = result.conn.Close()
					return zero, nil, ctx.Err()
				}
				return result.conn, result.remote, nil
			}
			errAll = errors.Join(errAll, fmt.Errorf("%s: %w", result.remote, result.err))
			accelerate = true
		}
	}
}

// raceUDPAddresses is the fixed-target test adapter for the same v2 racer.
func raceUDPAddresses[T io.Closer](ctx context.Context, targets []*net.UDPAddr, dial func(context.Context, *net.UDPAddr) (T, error)) (T, *net.UDPAddr, error) {
	var zero T
	if len(targets) == 0 {
		return zero, nil, errors.New("hysteria2 happy eyeballs: no targets")
	}
	ch := make(chan happyEyeballsBatch, 1)
	ch <- happyEyeballsBatch{addrs: targets}
	close(ch)
	return raceHappyEyeballsv2(ctx, ch, nil, false, dial)
}
