package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unique"

	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

type HappyEyeballsv2Cache interface {
	Load(key unique.Handle[string]) (net.IP, bool)
	Add(key unique.Handle[string], value net.IP, opt ...lru.AddOption[unique.Handle[string], net.IP])
}

var happyEyeballsCache = lru.NewSyncLru(lru.WithCapacity[unique.Handle[string], net.IP](512))

type happyEyeball struct {
	addr netapi.DomainAddress

	resolver                  netapi.Resolver
	dnsError                  error
	primaryDone, fallbackDone chan struct{}
	remainWait                chan struct{}
	ips                       []net.IP

	lastIp                    net.IP
	primaryMode, fallbackMode netapi.ResolverMode
	mu                        sync.Mutex
	allResponse               atomic.Int32

	prefer bool
}

func newHappyEyeball(ctx context.Context, addr netapi.DomainAddress, cache HappyEyeballsv2Cache) *happyEyeball {
	netctx := netapi.GetContext(ctx)
	resolver := Bootstrap
	if netctx.Resolver.ResolverSelf != nil {
		resolver = netctx.Resolver.ResolverSelf
	} else if netctx.Resolver.Resolver != nil {
		resolver = netctx.Resolver.Resolver
	}

	prefer := false
	primaryMode := netapi.ResolverModePreferIPv6
	fallbackMode := netapi.ResolverModePreferIPv4
	if netctx.Resolver.Mode == netapi.ResolverModePreferIPv4 {
		primaryMode = netapi.ResolverModePreferIPv4
		fallbackMode = netapi.ResolverModePreferIPv6
		prefer = true
	} else if netctx.Resolver.Mode == netapi.ResolverModePreferIPv6 {
		primaryMode = netapi.ResolverModePreferIPv6
		fallbackMode = netapi.ResolverModePreferIPv4
		prefer = true
	}

	var lastIP net.IP
	if cache != nil {
		lastIP, _ = cache.Load(addr.UniqueHostname())
	}
	h := &happyEyeball{
		addr:         addr,
		resolver:     resolver,
		primaryDone:  make(chan struct{}),
		fallbackDone: make(chan struct{}),
		primaryMode:  primaryMode,
		fallbackMode: fallbackMode,
		prefer:       prefer,
		lastIp:       lastIP,
	}

	h.remainWait = h.fallbackDone

	return h
}

func (h *happyEyeball) lookupIP(ctx context.Context, primary bool) {
	if h.prefer && !primary {
		return
	}

_retry:
	tmpIps, err := h.resolver.LookupIP(ctx, h.addr.Hostname(), func(li *netapi.LookupIPOption) {
		if primary {
			li.Mode = h.primaryMode
		} else {
			li.Mode = h.fallbackMode
		}
	})
	if err == nil {
		moveToFront(h.lastIp, tmpIps)
		h.mu.Lock()
		h.allResponse.Add(int32(len(tmpIps)))
		// Next, the client SHOULD modify the ordered list to interleave address
		// families.  Whichever address family is first in the list should be
		// followed by an address of the other address family; that is, if the
		// first address in the sorted list is IPv6, then the first IPv4 address
		// should be moved up in the list to be second in the list.
		if primary {
			h.ips = Interleave(tmpIps, h.ips)
		} else {
			h.ips = Interleave(h.ips, tmpIps)
		}
		h.mu.Unlock()
	} else {
		h.dnsError = errors.Join(h.dnsError, err)
		if h.prefer && primary {
			close(h.primaryDone)
			primary = false
			goto _retry
		}
	}

	if primary {
		close(h.primaryDone)
		if h.prefer {
			close(h.fallbackDone)
		}
	} else {
		close(h.fallbackDone)
	}
}

func (h *happyEyeball) waitFirstDNS(ctx context.Context) (err error) {
	select {
	case <-h.primaryDone:
	case <-h.fallbackDone:
		select {
		// If a positive
		// A response is received first due to reordering, the client SHOULD
		// wait a short time for the AAAA response to ensure that preference is
		// given to IPv6 (it is common for the AAAA response to follow the A
		// response by a few milliseconds).  This delay will be referred to as
		// the "Resolution Delay".  The recommended value for the Resolution
		// Delay is 50 milliseconds.
		case <-time.After(time.Millisecond * 50):
			h.remainWait = h.primaryDone
		case <-h.primaryDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	if h.allResponse.Load() == 0 {
		select {
		case <-h.remainWait:
			if h.allResponse.Load() == 0 {
				return fmt.Errorf("no ip found: %w", h.dnsError)
			}
		case <-ctx.Done():
			return fmt.Errorf("wait first dns timeout: %w", errors.Join(h.dnsError, ctx.Err()))
		}
	}

	return nil
}

func (h *happyEyeball) next(ctx context.Context) net.IP {
	if len(h.ips) != 0 {
		return h.nextIP()
	}

	select {
	case <-ctx.Done():
		return nil
	case <-h.remainWait:
	}

	if len(h.ips) == 0 {
		return nil
	}

	return h.nextIP()
}

func (h *happyEyeball) nextIP() net.IP {
	h.mu.Lock()
	ip := h.ips[0]
	h.ips = h.ips[1:]
	h.mu.Unlock()
	return ip
}

func (h *happyEyeball) allFailed(ctx context.Context, fails int, firstErr error) error {
	if fails == int(h.allResponse.Load()) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-h.remainWait:
		}
		if fails == int(h.allResponse.Load()) {
			return firstErr
		}
	}

	return nil
}

type HappyEyeballsv2Dialer[T net.Conn] struct {
	DialContext func(ctx context.Context, ip net.IP, port uint16) (T, error)
	Cache       HappyEyeballsv2Cache
}

var DefaultHappyEyeballsv2Dialer = &HappyEyeballsv2Dialer[net.Conn]{
	DialContext: func(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
		return DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	},
	Cache: happyEyeballsCache,
}

func (h *HappyEyeballsv2Dialer[T]) DialHappyEyeballsv2(ctx context.Context, addr netapi.Address) (t T, err error) {
	if !addr.IsFqdn() {
		return h.DialContext(ctx, addr.(netapi.IPAddress).IP(), addr.Port())
	}

	domainAddr, ok := addr.(netapi.DomainAddress)
	if !ok {
		return t, fmt.Errorf("unexpected address type %T", addr)
	}

	hb := newHappyEyeball(ctx, domainAddr, h.Cache)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go hb.lookupIP(ctx, true)
	if !hb.prefer {
		go hb.lookupIP(ctx, false)
	}

	if err := hb.waitFirstDNS(ctx); err != nil {
		return t, fmt.Errorf("wait first dns failed: %w", err)
	}

	type res struct {
		c   T
		err error
	}
	resc := make(chan res)           // must be unbuffered
	failBoost := make(chan struct{}) // best effort send on dial failure
	go func() {
		first := true
		for {
			if !first {
				// TODO use avg delay duration
				//
				// A simple implementation can have a fixed delay for how long to wait
				// before starting the next connection attempt.  This delay is referred
				// to as the "Connection Attempt Delay".  One recommended value for a
				// default delay is 250 milliseconds.
				timer := time.NewTimer(time.Millisecond * 300)
				select {
				case <-timer.C:
				case <-failBoost:
					timer.Stop()
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}

			ip := hb.next(ctx)
			if ip == nil {
				break
			}

			first = false

			go func(ip net.IP) {
				c, err := h.DialContext(ctx, ip, addr.Port())
				if err != nil {
					// Best effort wake-up a pending dial.
					// e.g. IPv4 dials failing quickly on an IPv6-only system.
					// In that case we don't want to wait 300ms per IPv4 before
					// we get to the IPv6 addresses.
					select {
					case failBoost <- struct{}{}:
					default:
					}
				}
				select {
				case resc <- res{c, err}:
				case <-ctx.Done():
					if err == nil {
						c.Close()
					}
				}
			}(ip)
		}
	}()

	var firstErr error
	var fails int
	for {
		select {
		case r := <-resc:
			if r.err == nil {
				if r.c.RemoteAddr() != nil {
					connAddr, ok := r.c.RemoteAddr().(*net.TCPAddr)
					if ok {
						if h.Cache != nil {
							h.Cache.Add(domainAddr.UniqueHostname(), connAddr.IP)
						}
					}
				}
				return r.c, nil
			}
			fails++
			if firstErr == nil {
				firstErr = r.err
			}
			if err := hb.allFailed(ctx, fails, firstErr); err != nil {
				metrics.Counter.AddTCPDialFailed(addr.String())
				return t, err
			}

		case <-ctx.Done():
			metrics.Counter.AddTCPDialFailed(addr.String())
			return t, fmt.Errorf("dial timeout: %w", errors.Join(firstErr, ctx.Err()))
		}
	}
}

// DialHappyEyeballsv2 impl rfc 8305
//
// https://datatracker.ietf.org/doc/html/rfc8305
// modified from https://github.com/tailscale/tailscale/blob/ee976ad704980e20ec36c6aaaad0a2ce5b30b3d5/net/dnscache/dnscache.go#L577
func DialHappyEyeballsv2(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return DefaultHappyEyeballsv2Dialer.DialHappyEyeballsv2(ctx, addr)
}

func moveToFront(ip net.IP, ips []net.IP) {
	if ip == nil {
		return
	}
	if (ip.To4() == nil && ips[0].To4() != nil) || (ip.To4() != nil && ips[0].To4() == nil) {
		return
	}
	for i, v := range ips {
		if v.Equal(ip) {
			ips[0], ips[i] = ips[i], ips[0]
			break
		}
	}
}

// Interleave combines two slices of the form [a, b, c] and [x, y, z] into a
// slice with elements interleaved; i.e. [a, x, b, y, c, z].
func Interleave[S ~[]T, T any](a, b S) S {
	// Avoid allocating an empty slice.
	if a == nil && b == nil {
		return nil
	}

	var (
		i   int
		ret = make([]T, 0, len(a)+len(b))
	)
	for i = 0; i < len(a) && i < len(b); i++ {
		ret = append(ret, a[i], b[i])
	}
	ret = append(ret, a[i:]...)
	ret = append(ret, b[i:]...)
	return ret
}
