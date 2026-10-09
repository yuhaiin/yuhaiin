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
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	dnssystem "github.com/Asutorufa/yuhaiin/pkg/net/dns/system"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/domain"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type Fakedns struct {
	// applyMu serializes pool changes and synchronous route notifications.
	// Callbacks run outside fakeMu so they cannot block DNS on a recursive lock.
	applyMu          sync.Mutex
	rangeHandlers    map[uint64]func([2]netip.Prefix) error
	nextRangeHandler uint64
	dialer           netapi.Proxy
	upstream         netapi.Resolver
	dbPath           string

	dnsServer netapi.DNSAgent
	fake      *fakeip.FakeDNS

	whitelist *domain.Fqdn[struct{}]
	skipCheck *domain.Fqdn[struct{}]

	serverHost string

	whitelistSlice []string
	skipCheckSlice []string

	smu     sync.RWMutex
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
	f.dnsServer = server.NewServer("", f)

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

	next, err := fakeip.NewFakeDNS(f.upstream, ipRange, ipv6Range, f.dbPath)
	if err != nil {
		return fmt.Errorf("reload sqlite fakeip pool failed: %w", err)
	}

	old := f.fake
	f.fake = next
	if old != nil {
		_ = old.Close()
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

	f.smu.Lock()
	defer f.smu.Unlock()

	if f.dnsServer != nil {
		if er := f.dnsServer.Close(); er != nil {
			err = errors.Join(err, er)
		}
		f.dnsServer = nil
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
	return f.dialer.Dispatch(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	return f.dialer.Conn(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return f.dialer.PacketConn(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return f.dialer.Ping(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) dispatchAddr(ctx context.Context, addr netapi.Address) netapi.Address {
	f.fakeMu.RLock()
	defer f.fakeMu.RUnlock()

	if addr.IsFqdn() {
		return addr
	}

	addrPort := addr.(netapi.IPAddress).AddrPort()
	if f.fake == nil {
		return addr
	}

	if !f.fake.Contains(addrPort.Addr()) {
		return addr
	}

	store := netapi.GetContext(ctx)

	t, ok := f.fake.GetDomainFromIP(addrPort.Addr())
	if ok {
		store.SetFakeIP(addr)
		z, err := netapi.ParseAddressPort(addr.Network(), t, addr.Port())
		if err == nil {
			store.SetDomainString(z.String())
			return z
		} else {
			log.Warn("parse fakeip reverse domain failed", "addr", t, "err", err)
		}
	}

	if configuration.FakeIPEnabled.Load() {
		// block fakeip range to prevent infinite loop which taget ip is not found in fakeip cache
		store.ConnOptions().SetRouteMode("block")
	}

	return addr
}

func (a *Fakedns) SetServer(s string) {
	var old netapi.DNSAgent

	a.smu.Lock()
	if a.serverHost == s {
		a.smu.Unlock()
		return
	}
	if a.dnsServer != nil {
		old = a.dnsServer
	}
	a.dnsServer = nil
	a.serverHost = s
	a.smu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			log.Error("close dns server failed", "err", err)
		}
	}

	next := server.NewServer(s, a)

	a.smu.Lock()
	a.dnsServer = next
	a.smu.Unlock()
}

func (a *Fakedns) server() netapi.DNSAgent {
	a.smu.RLock()
	defer a.smu.RUnlock()
	return a.dnsServer
}

func (a *Fakedns) DoStream(ctx context.Context, req *netapi.DNSStreamRequest) error {
	s := a.server()
	if s == nil {
		return fmt.Errorf("dns server is not initialized")
	}
	return s.DoStream(ctx, req)
}

func (a *Fakedns) DoDatagram(ctx context.Context, req *netapi.DNSRawRequest) error {
	s := a.server()
	if s == nil {
		return fmt.Errorf("dns server is not initialized")
	}
	return s.DoDatagram(ctx, req)
}
