package dialer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unique"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type HappyEyeballsv2Cache interface {
	Load(key unique.Handle[string]) (net.IP, bool)
	Add(key unique.Handle[string], value net.IP, opt ...lru.AddOption[unique.Handle[string], net.IP])
}

var happyEyeballsCache = lru.NewSyncLru(lru.WithCapacity[unique.Handle[string], net.IP](512))

type happyEyeball struct {
	addr netapi.DomainAddress

	resolver                  netapi.Resolver
	dnsErrorMu                sync.RWMutex
	dnsError                  error
	primaryDone, fallbackDone chan struct{}
	remainWait                chan struct{}
	ips                       []net.IP

	lastIp                    net.IP
	primaryMode, fallbackMode netapi.ResolverMode
	mu                        sync.RWMutex
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
		h.dnsErrorMu.Lock()
		h.dnsError = MergeDnsError(h.dnsError, err)
		h.dnsErrorMu.Unlock()
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

func MergeDnsError(err1, err2 error) error {
	de1 := &net.DNSError{}

	if !errors.As(err1, &de1) {
		return errors.Join(err1, err2)
	}

	de2 := &net.DNSError{}
	if !errors.As(err2, &de2) {
		return errors.Join(err1, err2)
	}

	if de1.Err == de2.Err {
		return err1
	}

	return errors.Join(err1, err2)
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
				h.dnsErrorMu.RLock()
				dnsError := h.dnsError
				h.dnsErrorMu.RUnlock()
				return fmt.Errorf("no ip found: %w", dnsError)
			}
		case <-ctx.Done():
			h.dnsErrorMu.RLock()
			dnsError := h.dnsError
			h.dnsErrorMu.RUnlock()
			return fmt.Errorf("wait first dns timeout: %w", errors.Join(dnsError, ctx.Err()))
		}
	}

	return nil
}

func (h *happyEyeball) next(ctx context.Context) net.IP {
	h.mu.RLock()
	ipslen := len(h.ips)
	h.mu.RUnlock()
	if ipslen != 0 {
		return h.nextIP()
	}

	select {
	case <-ctx.Done():
		return nil
	case <-h.remainWait:
	}
	h.mu.RLock()
	ipslen = len(h.ips)
	h.mu.RUnlock()
	if ipslen == 0 {
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

var DefaultIPv6PreferUnicastLocalAddr = false

type HappyEyeballsv2Dialer[T net.Conn] struct {
	DialContext func(ctx context.Context, ip net.IP, port uint16) (T, error)
	Cache       HappyEyeballsv2Cache
	Avg         *Avg
}

var DefaultHappyEyeballsv2Dialer = &HappyEyeballsv2Dialer[net.Conn]{
	DialContext: func(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
		return DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), func(opts *Options) {
			if DefaultIPv6PreferUnicastLocalAddr && opts.InterfaceName != "" || opts.InterfaceIndex != 0 {
				if ip.IsGlobalUnicast() && !ip.IsPrivate() && ip.To4() == nil && ip.To16() != nil {
					opts.LocalAddr = GetUnicastAddr(true, "tcp", opts.InterfaceName, opts.InterfaceIndex)
					log.Info("happy eyeballs dialer prefer ipv6", slog.Any("localaddr", opts.LocalAddr))
				}
			}
		})
	},
	Cache: happyEyeballsCache,
	Avg:   NewAvg(),
}

func (h *HappyEyeballsv2Dialer[T]) DialHappyEyeballsv2(ctx context.Context, addr netapi.Address) (t T, err error) {
	if h.Avg == nil {
		h.Avg = NewAvg()
	}

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
				// A simple implementation can have a fixed delay for how long to wait
				// before starting the next connection attempt.  This delay is referred
				// to as the "Connection Attempt Delay".  One recommended value for a
				// default delay is 250 milliseconds. A more nuanced implementation's
				// delay should correspond to the time when the previous attempt is
				// sending its second TCP SYN, based on the TCP's retransmission timer
				// [RFC6298].  If the client has historical RTT data gathered from other
				// connections to the same host or prefix, it can use this information
				// to influence its delay.  Note that this algorithm should only try to
				// approximate the time of the first SYN retransmission, and not any
				// further retransmissions that may be influenced by exponential timer
				// back off.
				// log.Info("use timer for delay", "avg", h.Avg.Get())
				timer := time.NewTimer(h.Avg.Get())
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
				start := system.CheapNowNano()

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
				} else {
					h.Avg.Push(time.Duration(system.CheapNowNano() - start))
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

func GetUnicastAddr(ipv6 bool, network string, name string, index int) net.Addr {
	if len(network) < 3 {
		return nil
	}

	var ifs *net.Interface
	var err error

	if name != "" {
		ifs, err = net.InterfaceByName(name)
	} else if index != 0 {
		ifs, err = net.InterfaceByIndex(index)
	} else {
		return nil
	}
	if err != nil {
		return nil
	}

	addrs, err := ifs.Addrs()
	if err != nil {
		return nil
	}

	for _, v := range addrs {
		x, ok := v.(*net.IPNet)
		if !ok || x.IP == nil {
			continue
		}

		if ipv6 && x.IP.To4() != nil {
			continue
		} else if !ipv6 && x.IP.To4() == nil {
			continue
		}

		if x.IP.IsGlobalUnicast() && !x.IP.IsPrivate() {

			switch network[:3] {
			case "tcp":
				return &net.TCPAddr{
					IP: x.IP,
				}
			case "udp":
				return &net.UDPAddr{
					IP: x.IP,
				}
			}
		}
	}

	return nil
}
