package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	id "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

type Fakedns struct {
	enabled  bool
	fake     *dns.FakeDNS
	dialer   proxy.Proxy
	upstream id.DNS
	cache    *cache.Cache

	// current dns client(fake/upstream)
	id.DNS
}

func NewFakeDNS(dialer proxy.Proxy, upstream id.DNS, bbolt *cache.Cache) *Fakedns {
	return &Fakedns{
		fake:     dns.NewFakeDNS(upstream, yerror.Ignore(netip.ParsePrefix("10.2.0.1/24")), bbolt),
		dialer:   dialer,
		upstream: upstream,
		DNS:      upstream,
		cache:    bbolt,
	}
}

func (f *Fakedns) Update(c *pc.Setting) {
	f.enabled = c.Dns.Fakedns

	ipRange, err := netip.ParsePrefix(c.Dns.FakednsIpRange)
	if err != nil {
		log.Errorln("parse fakedns ip range failed:", err)
		return
	}
	f.fake = dns.NewFakeDNS(f.upstream, ipRange, f.cache)

	if f.enabled {
		f.DNS = f.fake
	} else {
		f.DNS = f.upstream
	}
}

func (f *Fakedns) Dispatch(ctx context.Context, addr proxy.Address) (proxy.Address, error) {
	return f.dialer.Dispatch(ctx, f.getAddr(addr))
}

func (f *Fakedns) Conn(ctx context.Context, addr proxy.Address) (net.Conn, error) {
	c, err := f.dialer.Conn(ctx, f.getAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("connect tcp to %s failed: %w", addr, err)
	}

	return c, nil
}

func (f *Fakedns) PacketConn(ctx context.Context, addr proxy.Address) (net.PacketConn, error) {
	c, err := f.dialer.PacketConn(ctx, f.getAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("connect udp to %s failed: %w", addr, err)
	}

	if f.enabled {
		c = &dispatchPacketConn{c, f.getAddr}
	}

	return c, nil
}

func (f *Fakedns) getAddr(addr proxy.Address) proxy.Address {
	if f.enabled && addr.Type() == proxy.IP {
		t, ok := f.fake.GetDomainFromIP(addr.Hostname())
		if ok {
			r := addr.OverrideHostname(t)
			r.WithValue(proxy.FakeIPKey{}, addr)
			r.WithValue(proxy.CurrentKey{}, r)
			return r
		}
	}
	return addr
}

type dispatchPacketConn struct {
	net.PacketConn
	dispatch func(proxy.Address) proxy.Address
}

func (f *dispatchPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	z, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("parse addr failed: %w", err)
	}

	return f.PacketConn.WriteTo(b, f.dispatch(z))
}
