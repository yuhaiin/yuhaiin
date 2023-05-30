package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

type Fakedns struct {
	enabled  bool
	fake     *dns.FakeDNS
	dialer   proxy.Proxy
	upstream proxy.Resolver
	cache    *cache.Cache

	// current dns client(fake/upstream)
	proxy.Resolver
}

func NewFakeDNS(dialer proxy.Proxy, upstream proxy.Resolver, bbolt *cache.Cache) *Fakedns {
	return &Fakedns{
		fake:     dns.NewFakeDNS(upstream, yerror.Ignore(netip.ParsePrefix("10.2.0.1/24")), bbolt),
		dialer:   dialer,
		upstream: upstream,
		Resolver: upstream,
		cache:    bbolt,
	}
}

func (f *Fakedns) Update(c *pc.Setting) {
	f.enabled = c.Dns.Fakedns

	ipRange, err := netip.ParsePrefix(c.Dns.FakednsIpRange)
	if err != nil {
		log.Error("parse fakedns ip range failed", "err", err)
		return
	}
	f.fake = dns.NewFakeDNS(f.upstream, ipRange, f.cache)

	if f.enabled {
		f.Resolver = f.fake
	} else {
		f.Resolver = f.upstream
	}
}

func (f *Fakedns) Dispatch(ctx context.Context, addr proxy.Address) (proxy.Address, error) {
	return f.dialer.Dispatch(ctx, f.dispatchAddr(ctx, addr))
}

func (f *Fakedns) Conn(ctx context.Context, addr proxy.Address) (net.Conn, error) {
	c, err := f.dialer.Conn(ctx, f.dispatchAddr(ctx, addr))
	if err != nil {
		return nil, fmt.Errorf("connect tcp to %s failed: %w", addr, err)
	}

	return c, nil
}

func (f *Fakedns) PacketConn(ctx context.Context, addr proxy.Address) (net.PacketConn, error) {
	c, err := f.dialer.PacketConn(ctx, f.dispatchAddr(ctx, addr))
	if err != nil {
		return nil, fmt.Errorf("connect udp to %s failed: %w", addr, err)
	}

	if f.enabled {
		c = &dispatchPacketConn{c, f.dispatchAddr}
	}

	return c, nil
}

func (f *Fakedns) dispatchAddr(ctx context.Context, addr proxy.Address) proxy.Address {
	if f.enabled && addr.Type() == proxy.IP {
		t, ok := f.fake.GetDomainFromIP(yerror.Ignore(addr.AddrPort(ctx)).Addr())
		if ok {
			r := addr.OverrideHostname(t)
			proxy.StoreFromContext(ctx).
				Add(proxy.FakeIPKey{}, addr).
				Add(proxy.CurrentKey{}, r)
			return r
		}
	}
	return addr
}

type dispatchPacketConn struct {
	net.PacketConn
	dispatch func(context.Context, proxy.Address) proxy.Address
}

func (f *dispatchPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	z, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("parse addr failed: %w", err)
	}

	return f.PacketConn.WriteTo(b, f.dispatch(context.TODO(), z))
}
