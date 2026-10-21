package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/fakeip"
	dnssystem "github.com/Asutorufa/yuhaiin/pkg/net/dns/system"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

var ErrUnmappedFakeIP = errors.New("fakeip: address is within the synthetic pool but has no mapping")

type Fakedns struct {
	// applyMu serializes pool changes and synchronous route notifications.
	// Callbacks run outside fakeMu so they cannot block DNS on a recursive lock.
	applyMu          sync.Mutex
	rangeHandlers    map[uint64]func([2]netip.Prefix) error
	nextRangeHandler uint64
	dialer           netapi.Proxy
	upstream         netapi.Resolver
	dbPath           string
	fake             *fakeip.FakeDNS

	whitelist *domain.Fqdn[struct{}]
	skipCheck *domain.Fqdn[struct{}]

	whitelistSlice []string
	skipCheckSlice []string

	fakeMu  sync.RWMutex
	enabled atomic.Bool
}

func NewFakeDNS(dialer netapi.Proxy, upstream netapi.Resolver, dbPath string, initial ...contractresolver.FakeDNS) (*Fakedns, error) {
	ipv4Range := configuration.GetFakeIPRange("", false)
	ipv6Range := configuration.GetFakeIPRange("", true)
	if len(initial) > 0 {
		ipv4Range = configuration.GetFakeIPRange(initial[0].IPv4Range, false)
		ipv6Range = configuration.GetFakeIPRange(initial[0].IPv6Range, true)
	}

	fake, err := fakeip.NewFakeDNS(upstream, ipv4Range, ipv6Range, dbPath)
	if err != nil {
		return nil, err
	}

	f := &Fakedns{
		fake:      fake,
		dialer:    dialer,
		upstream:  upstream,
		dbPath:    dbPath,
		whitelist: domain.NewTrie[struct{}](),
		skipCheck: domain.NewTrie[struct{}](),
	}
	return f, nil
}

// Apply notifies route consumers only after the pool update succeeds. It also
// retries consumers when the ranges are unchanged (e.g. a failed route deletion).
func (f *Fakedns) Apply(c contractresolver.FakeDNS) error {
	f.applyMu.Lock()
	defer f.applyMu.Unlock()
	if err := f.apply(c); err != nil {
		return err
	}
	ranges := f.FakeIPRanges()
	var result error
	for _, handler := range f.rangeHandlers {
		result = errors.Join(result, handler(ranges))
	}
	return result
}

func (f *Fakedns) FakeIPRanges() [2]netip.Prefix {
	f.fakeMu.RLock()
	defer f.fakeMu.RUnlock()
	if f.fake == nil {
		return [2]netip.Prefix{}
	}
	return f.fake.Ranges()
}

// SubscribeFakeIPRanges supplies an initial snapshot and serializes subsequent
// notifications with registration and cancellation. A cancelled subscription
// has no callback in flight when cancellation returns.
func (f *Fakedns) SubscribeFakeIPRanges(handler func([2]netip.Prefix) error) (func(), error) {
	f.applyMu.Lock()
	defer f.applyMu.Unlock()
	ranges := f.FakeIPRanges()
	if !ranges[0].IsValid() || !ranges[1].IsValid() {
		return nil, errors.New("fake DNS is closed")
	}
	if err := handler(ranges); err != nil {
		return nil, err
	}
	if f.rangeHandlers == nil {
		f.rangeHandlers = make(map[uint64]func([2]netip.Prefix) error)
	}
	f.nextRangeHandler++
	id := f.nextRangeHandler
	f.rangeHandlers[id] = handler
	return sync.OnceFunc(func() {
		f.applyMu.Lock()
		defer f.applyMu.Unlock()
		delete(f.rangeHandlers, id)
	}), nil
}

func (f *Fakedns) apply(c contractresolver.FakeDNS) error {
	defer dnssystem.RefreshCache()

	f.fakeMu.Lock()
	defer f.fakeMu.Unlock()
	if f.fake == nil {
		return errors.New("fake DNS is closed")
	}

	f.enabled.Store(c.Enabled)

	if !slices.Equal(c.SkipCheckList, f.skipCheckSlice) {
		d := domain.NewTrie[struct{}]()

		for _, v := range c.SkipCheckList {
			d.Insert(v, struct{}{})
		}
		f.skipCheck = d
		f.skipCheckSlice = c.SkipCheckList
	}

	if !slices.Equal(c.Whitelist, f.whitelistSlice) {
		d := domain.NewTrie[struct{}]()

		for _, v := range c.Whitelist {
			d.Insert(v, struct{}{})
		}

		// skip tailscale login url, because tailscale client will use default
		// interface to connect controlplane, so we can't use fake ip for it
		// d.Insert(strings.TrimPrefix(ipn.DefaultControlURL, "https://"), struct{}{})
		// d.Insert(logtail.DefaultHost, struct{}{})
		// d.Insert("login.tailscale.com", struct{}{})

		f.whitelist = d
		f.whitelistSlice = c.Whitelist
	}

	ipRange := configuration.GetFakeIPRange(c.IPv4Range, false)
	ipv6Range := configuration.GetFakeIPRange(c.IPv6Range, true)

	if f.fake.Equal(ipRange, ipv6Range) {
		return nil
	}

	if err := f.fake.Reconfigure(ipRange, ipv6Range, f.dbPath); err != nil {
		return fmt.Errorf("reload sqlite fakeip pool failed: %w", err)
	}
	return nil
}

func (f *Fakedns) resolver(ctx context.Context, domain string) netapi.Resolver {
	metrics.Counter.AddDNSProcess(domain)

	if f.enabled.Load() || netapi.GetContext(ctx).ConnOptions().Resolver().UseFakeIP() {
		if _, ok := f.whitelist.SearchString(system.RelDomain(domain)); ok {
			return f.upstream
		}

		return f.fake
	}

	return f.upstream
}

func (f *Fakedns) LookupIP(ctx context.Context, domain string, opts ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	f.fakeMu.RLock()
	defer f.fakeMu.RUnlock()

	if _, ok := f.skipCheck.SearchString(system.RelDomain(domain)); ok {
		netapi.GetContext(ctx).ConnOptions().Resolver().SetFakeIPSkipCheckUpstream(ok)
	}
	return f.resolver(ctx, domain).LookupIP(ctx, domain, opts...)
}

func (f *Fakedns) Raw(ctx context.Context, req netapi.DNSQuestion) (*dns.Msg, error) {
	f.fakeMu.RLock()
	defer f.fakeMu.RUnlock()

	if req.Qtype == dns.TypeAAAA || req.Qtype == dns.TypeA {
		if _, ok := f.skipCheck.SearchString(system.RelDomain(req.Name)); ok {
			netapi.GetContext(ctx).ConnOptions().Resolver().SetFakeIPSkipCheckUpstream(ok)
		}
	}
	return f.resolver(ctx, req.Name).Raw(ctx, req)
}

func (f *Fakedns) Close() error {
	f.applyMu.Lock()
	defer f.applyMu.Unlock()
	f.rangeHandlers = nil
	var err error

	f.fakeMu.Lock()
	defer f.fakeMu.Unlock()

	if er := f.upstream.Close(); er != nil {
		err = errors.Join(err, er)
	}

	if f.fake != nil {
		if er := f.fake.Close(); er != nil {
			err = errors.Join(err, er)
		}
		f.fake = nil
	}

	return err
}

func (f *Fakedns) Name() string { return "fakedns" }

func (f *Fakedns) Dispatch(ctx context.Context, addr netapi.Address) (netapi.Address, error) {
	target, _, err := f.recoverDestination(ctx, addr, false)
	if err != nil {
		return nil, err
	}
	return f.dialer.Dispatch(ctx, target)
}

// RecoverDestination restores FakeIP identity without performing L4 selection.
// Callers with no error return still carry an irrevocable block marker.
func (f *Fakedns) RecoverDestination(ctx context.Context, addr netapi.Address) netapi.Address {
	return f.dispatchAddr(ctx, addr)
}

// LeaseDestination pins a synthetic destination retained by a caller such as
// a full-cone UDP session. The caller releases it when its cached mapping ends.
func (f *Fakedns) LeaseDestination(ctx context.Context, addr netapi.Address) (func(), error) {
	_, release, err := f.recoverDestination(ctx, addr, true)
	return release, err
}

// ConnWithLease preserves the FakeIP identity recovered before Gateway route
// selection while the selected outbound connection remains open.
func (f *Fakedns) ConnWithLease(ctx context.Context, addr netapi.Address, dial func() (net.Conn, error)) (net.Conn, error) {
	// Gateway selection may already have recovered the domain and applied
	// hosts mappings. Pin the original FakeIP without changing that selection.
	if original := netapi.GetContext(ctx).GetFakeIP(); original != nil {
		var err error
		addr, err = netapi.ParseSysAddr(original)
		if err != nil {
			return nil, err
		}
	}
	release, err := f.LeaseDestination(ctx, addr)
	if err != nil {
		return nil, err
	}
	conn, err := dial()
	if err != nil {
		if release != nil {
			release()
		}
		return nil, err
	}
	if release != nil {
		return &leasedFakeIPConn{Conn: conn, release: release}, nil
	}
	return conn, nil
}

type leasedFakeIPConn struct {
	net.Conn
	release func()
}

func (c *leasedFakeIPConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

type leasedFakeIPPacketConn struct {
	net.PacketConn
	release func()
}

func (c *leasedFakeIPPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.release()
	return err
}

func (f *Fakedns) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	target, release, err := f.recoverDestination(ctx, addr, true)
	if err != nil {
		return nil, err
	}
	conn, err := f.dialer.Conn(ctx, target)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, err
	}
	if release != nil {
		return &leasedFakeIPConn{Conn: conn, release: release}, nil
	}
	return conn, nil
}

func (f *Fakedns) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	target, release, err := f.recoverDestination(ctx, addr, true)
	if err != nil {
		return nil, err
	}
	conn, err := f.dialer.PacketConn(ctx, target)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, err
	}
	if release != nil {
		return &leasedFakeIPPacketConn{PacketConn: conn, release: release}, nil
	}
	return conn, nil
}

func (f *Fakedns) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	target, release, err := f.recoverDestination(ctx, addr, true)
	if err != nil {
		return 0, err
	}
	if release != nil {
		defer release()
	}
	return f.dialer.Ping(ctx, target)
}

func (f *Fakedns) dispatchAddr(ctx context.Context, addr netapi.Address) netapi.Address {
	target, _, _ := f.recoverDestination(ctx, addr, false)
	return target
}

// recoverDestination treats an unmapped synthetic destination as invalid even
// when FakeDNS is now disabled. Never leak it to a direct/proxy outbound or
// allow a previous route-mode override to bypass the block.
func (f *Fakedns) recoverDestination(ctx context.Context, addr netapi.Address, lease bool) (netapi.Address, func(), error) {
	if addr.IsFqdn() {
		return addr, nil, nil
	}
	ipAddr, ok := addr.(netapi.IPAddress)
	if !ok {
		return addr, nil, nil
	}
	addrPort := ipAddr.AddrPort()

	f.fakeMu.RLock()
	defer f.fakeMu.RUnlock()
	if f.fake == nil || !f.fake.Contains(addrPort.Addr()) {
		return addr, nil, nil
	}

	var domain string
	var release func()
	if lease {
		domain, release, ok = f.fake.LeaseDomainFromIP(addrPort.Addr())
	} else {
		domain, ok = f.fake.GetDomainFromIP(addrPort.Addr())
	}
	store := netapi.GetContext(ctx)
	if ok {
		target, err := netapi.ParseAddressPort(addr.Network(), domain, addr.Port())
		if err == nil {
			store.SetFakeIP(addr)
			store.SetDomainString(target.String())
			return target, release, nil
		}
		if release != nil {
			release()
		}
		log.Warn("parse fakeip reverse domain failed", "domain", domain, "err", err)
	}
	store.ConnOptions().MarkUnmappedFakeIP()
	store.ConnOptions().SetRouteMode("block")
	return addr, nil, ErrUnmappedFakeIP
}
