package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type HappyEyeballsv2Cache interface {
	Load(key string) (net.IP, bool)
	Add(key string, value net.IP, opt ...lru.AddOption[string, net.IP])
}

func WithHappyEyeballsSemaphore[T net.Conn](semaphore semaphore.Semaphore) func(*HappyEyeballsv2Dialer[T]) {
	return func(d *HappyEyeballsv2Dialer[T]) {
		d.semaphore = semaphore
	}
}

func WithHappyEyeballsCache[T net.Conn](cache HappyEyeballsv2Cache) func(*HappyEyeballsv2Dialer[T]) {
	return func(d *HappyEyeballsv2Dialer[T]) {
		d.cache = cache
	}
}

func WithHappyEyeballsAvg[T net.Conn](avg *Avg) func(*HappyEyeballsv2Dialer[T]) {
	return func(d *HappyEyeballsv2Dialer[T]) {
		d.avg = avg
	}
}

var DefaultHappyEyeballsv2Dialer = atomicx.NewValue(NewDefaultHappyEyeballsv2Dialer())

func NewDefaultHappyEyeballsv2Dialer(opts ...func(*HappyEyeballsv2Dialer[net.Conn])) *HappyEyeballsv2Dialer[net.Conn] {
	return NewHappyEyeballsv2Dialer(func(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
		return DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	}, opts...)
}

func NewHappyEyeballsv2Dialer[T net.Conn](dialer func(ctx context.Context, ip net.IP, port uint16) (T, error),
	opts ...func(*HappyEyeballsv2Dialer[T])) *HappyEyeballsv2Dialer[T] {
	ret := &HappyEyeballsv2Dialer[T]{
		dialContext: dialer,
		cache:       lru.NewSyncLru(lru.WithCapacity[string, net.IP](512)),
		avg:         NewAvg(),
		semaphore:   semaphore.NewEmptySemaphore(),
	}

	for _, opt := range opts {
		opt(ret)
	}

	return ret
}

// DialHappyEyeballsv2 impl rfc 8305
//
// https://datatracker.ietf.org/doc/html/rfc8305
// modified from https://github.com/tailscale/tailscale/blob/ee976ad704980e20ec36c6aaaad0a2ce5b30b3d5/net/dnscache/dnscache.go#L577
func DialHappyEyeballsv2(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return DefaultHappyEyeballsv2Dialer.Load().DialHappyEyeballsv2(ctx, addr)
}

func moveToFront(ip net.IP, ips []net.IP) {
	if ip == nil || len(ips) == 0 {
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

type happyEyeballv2Resolver struct {
	ctx    context.Context
	cancel context.CancelFunc

	addr                      netapi.Address
	resolver                  netapi.Resolver
	primaryMode, fallbackMode netapi.ResolverMode

	ips    []net.IP
	lastIp net.IP
	mu     sync.Mutex

	notify chan struct{}
	errors error
}

func ifElse[T any](cond bool, trueVal, falseVal T) T {
	if cond {
		return trueVal
	}
	return falseVal
}

func newHappyEyeballv2Respover(ctx context.Context, addr netapi.Address,
	cache HappyEyeballsv2Cache, semaphore semaphore.Semaphore) *happyEyeballv2Resolver {
	ctx, cancel := context.WithCancel(ctx)

	var lastIP net.IP
	if cache != nil {
		lastIP, _ = cache.Load(addr.Hostname())
	}

	netctx := netapi.GetContext(ctx)

	r := &happyEyeballv2Resolver{
		ctx:          ctx,
		cancel:       cancel,
		addr:         addr,
		resolver:     netctx.Resolver.ResolverResolver(Bootstrap()),
		primaryMode:  netapi.ResolverModePreferIPv6,
		fallbackMode: netapi.ResolverModePreferIPv4,
		lastIp:       lastIP,
		notify:       make(chan struct{}, 2),
	}

	var prefer bool
	switch netctx.Resolver.Mode {
	case netapi.ResolverModePreferIPv4:
		r.primaryMode, r.fallbackMode, prefer = netapi.ResolverModePreferIPv4, netapi.ResolverModePreferIPv6, true
	case netapi.ResolverModePreferIPv6:
		prefer = true
	}

	if err := semaphore.Acquire(ctx, ifElse[int64](prefer, 1, 2)); err != nil {
		cancel()
		r.errors = fmt.Errorf("failed to acquire semaphore: %w", err)
		return r
	}

	if prefer {
		go func() {
			defer semaphore.Release(1)
			defer cancel()

			r.do(true)
			if r.errors != nil {
				r.do(false)
			}
		}()

		return r
	}

	go func() {
		var wg sync.WaitGroup

		wg.Go(func() {
			defer semaphore.Release(1)
			r.do(true)

			select {
			case r.notify <- struct{}{}:
			case <-ctx.Done():
			}
		})

		wg.Go(func() {
			defer semaphore.Release(1)
			r.do(false)
			// If a positive
			// A response is received first due to reordering, the client SHOULD
			// wait a short time for the AAAA response to ensure that preference is
			// given to IPv6 (it is common for the AAAA response to follow the A
			// response by a few milliseconds).  This delay will be referred to as
			// the "Resolution Delay".  The recommended value for the Resolution
			// Delay is 50 milliseconds.
			time.Sleep(time.Millisecond * 50)

			select {
			case r.notify <- struct{}{}:
			case <-ctx.Done():
			}
		})

		wg.Wait()
		cancel()
	}()

	return r
}

func (h *happyEyeballv2Resolver) do(primary bool) {
	tmpIps, err := h.resolver.LookupIP(h.ctx, h.addr.Hostname(), func(li *netapi.LookupIPOption) {
		if primary {
			li.Mode = h.primaryMode
		} else {
			li.Mode = h.fallbackMode
		}
	})

	h.mu.Lock()
	if err == nil {
		moveToFront(h.lastIp, tmpIps.WhoNotEmpty())
		// Next, the client SHOULD modify the ordered list to interleave address
		// families.  Whichever address family is first in the list should be
		// followed by an address of the other address family; that is, if the
		// first address in the sorted list is IPv6, then the first IPv4 address
		// should be moved up in the list to be second in the list.
		if primary {
			h.ips = Interleave(tmpIps.WhoNotEmpty(), h.ips)
		} else {
			h.ips = Interleave(h.ips, tmpIps.WhoNotEmpty())
		}
	} else {
		h.errors = MergeDnsError(h.errors, err)
	}
	h.mu.Unlock()
}

func (h *happyEyeballv2Resolver) wait() (net.IP, error) {
	for {
		h.mu.Lock()
		if len(h.ips) <= 0 {
			h.mu.Unlock()

			select {
			case <-h.notify:
				continue
			case <-h.ctx.Done():
				h.mu.Lock()
				l := len(h.ips)
				errors := h.errors
				h.mu.Unlock()
				if l == 0 {
					if errors != nil {
						return nil, errors
					}

					return nil, h.ctx.Err()
				}

				continue
			}
		}

		ip := h.ips[0]
		h.ips = h.ips[1:]
		h.mu.Unlock()

		return ip, nil
	}
}

type HappyEyeballsv2Dialer[T net.Conn] struct {
	dialContext func(ctx context.Context, ip net.IP, port uint16) (T, error)
	cache       HappyEyeballsv2Cache
	avg         *Avg
	semaphore   semaphore.Semaphore
}

func (h *HappyEyeballsv2Dialer[T]) SemaphoreWeight() int64 {
	return h.semaphore.Weight()
}

func (h *HappyEyeballsv2Dialer[T]) DialHappyEyeballsv2(octx context.Context, addr netapi.Address) (t T, err error) {
	if h.avg == nil {
		h.avg = NewAvg()
	}

	if !addr.IsFqdn() {
		return h.dialContext(octx, addr.(netapi.IPAddress).AddrPort().Addr().AsSlice(), addr.Port())
	}

	ctx, cancel := context.WithCancelCause(octx)
	defer cancel(context.Canceled)

	hb := newHappyEyeballv2Respover(ctx, addr, h.cache, h.semaphore)

	type res struct {
		c   T
		err error
	}
	resc := make(chan res) // must be unbuffered
	go func() {
		var (
			failBoost = make(chan struct{}) // best effort send on dial failure
			wg        sync.WaitGroup
			err       error
		)

	_loop:
		for {
			var ip net.IP
			ip, err = hb.wait()
			if err != nil {
				break _loop
			}

			if err := h.semaphore.Acquire(ctx, 1); err != nil {
				log.Warn("acquire semaphore failed", "err", err)
				break _loop
			}

			wg.Go(func() {
				defer h.semaphore.Release(1)

				start := system.CheapNowNano()

				c, err := h.dialContext(ctx, ip, addr.Port())
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
					h.avg.Push(time.Duration(system.CheapNowNano() - start))
				}

				select {
				case resc <- res{c, err}:
				case <-ctx.Done():
					if err == nil {
						_ = c.Close()
					}
				}
			})

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
			timer := time.NewTimer(h.avg.Get())
			select {
			case <-timer.C:
			case <-failBoost:
				timer.Stop()
			case <-ctx.Done():
				timer.Stop()
				return
			}
		}

		wg.Wait()
		cancel(err)
	}()

	var dialErrors error
	for {
		select {
		case r := <-resc:
			if r.err != nil {
				dialErrors = errors.Join(dialErrors, r.err)
				continue
			}

			if r.c.RemoteAddr() != nil {
				if connAddr, ok := r.c.RemoteAddr().(*net.TCPAddr); ok && h.cache != nil {
					h.cache.Add(addr.Hostname(), connAddr.IP)
				}
			}

			return r.c, nil

		case <-ctx.Done():
			metrics.Counter.AddTCPDialFailed(addr.String())
			if dialErrors != nil {
				return t, dialErrors
			}

			return t, fmt.Errorf("dial context done: %w", context.Cause(ctx))
		}
	}
}
