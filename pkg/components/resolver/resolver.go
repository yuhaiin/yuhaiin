package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/components/config"
	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"
)

func NewBootstrap(dl netapi.Proxy) netapi.Resolver {
	bootstrap := wrap("BOOTSTRAP", func(b *dnsWrap, c *pc.Setting) {
		if proto.Equal(b.config, c.Dns.Bootstrap) && b.ipv6 == c.GetIpv6() {
			return
		}

		if err := config.CheckBootstrapDns(c.Dns.Bootstrap); err != nil {
			log.Error("check bootstrap dns failed", "err", err)
			return
		}

		b.config = c.Dns.Bootstrap
		b.ipv6 = c.GetIpv6()
		b.Close()

		z, err := newDNS("BOOTSTRAP", c.GetIpv6(), b.config,
			&dialer{
				Proxy: dl,
				addr: func(ctx context.Context, addr netapi.Address) {
					netapi.StoreFromContext(ctx).Add(shunt.ForceModeKey{}, bypass.Mode_direct)
					addr.SetResolver(netapi.NewSystemResolver(c.GetIpv6()))
					addr.SetSrc(netapi.AddressSrcDNS)
				}},
		)
		if err != nil {
			log.Error("get bootstrap dns failed", "err", err)
		} else {
			b.dns = z
		}
	})
	netapi.Bootstrap = bootstrap

	return bootstrap
}

func NewLocal(dl netapi.Proxy) netapi.Resolver {
	return wrap("LOCALDNS", func(l *dnsWrap, c *pc.Setting) {
		if proto.Equal(l.config, c.Dns.Local) && l.ipv6 == c.GetIpv6() {
			return
		}

		l.config = c.Dns.Local
		l.ipv6 = c.GetIpv6()
		l.Close()
		z, err := newDNS("LOCALDNS", c.GetIpv6(), l.config, &dialer{
			Proxy: dl,
			addr: func(ctx context.Context, addr netapi.Address) {
				// force to use bootstrap dns, otherwise will dns query cycle
				addr.SetResolver(netapi.Bootstrap)
				addr.SetSrc(netapi.AddressSrcDNS)
			},
		})
		if err != nil {
			log.Error("get local dns failed", "err", err)
		} else {
			l.dns = z
		}
	})
}

func NewRemote(dl netapi.Proxy) netapi.Resolver {
	return wrap("REMOTEDNS", func(r *dnsWrap, c *pc.Setting) {
		if proto.Equal(r.config, c.Dns.Remote) && r.ipv6 == c.GetIpv6() {
			return
		}

		r.config = c.Dns.Remote
		r.ipv6 = c.GetIpv6()
		r.Close()
		z, err := newDNS("REMOTEDNS", c.GetIpv6(), r.config,
			&dialer{
				Proxy: dl,
				addr: func(ctx context.Context, addr netapi.Address) {
					// force to use bootstrap dns, otherwise will dns query cycle
					addr.SetResolver(netapi.Bootstrap)
					addr.SetSrc(netapi.AddressSrcDNS)
				},
			})
		if err != nil {
			log.Error("get remote dns failed", "err", err)
		} else {
			r.dns = z
		}
	})
}

type dnsWrap struct {
	ipv6   bool
	config *pd.Dns
	name   string
	dns    netapi.Resolver

	update func(*dnsWrap, *pc.Setting)
}

func wrap(name string, update func(*dnsWrap, *pc.Setting)) *dnsWrap {
	return &dnsWrap{update: update, name: name}
}

func (d *dnsWrap) Update(c *pc.Setting) { d.update(d, c) }

func (d *dnsWrap) LookupIP(ctx context.Context, host string, opts ...func(*netapi.LookupIPOption)) ([]net.IP, error) {
	if d.dns == nil {
		return nil, fmt.Errorf("%s dns not initialized", d.name)
	}

	ips, err := d.dns.LookupIP(ctx, host, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s lookup failed: %w", d.name, err)
	}

	return ips, nil
}

func (d *dnsWrap) Raw(ctx context.Context, req dnsmessage.Question) (dnsmessage.Message, error) {
	if d.dns == nil {
		return dnsmessage.Message{}, fmt.Errorf("%s dns not initialized", d.name)
	}

	msg, err := d.dns.Raw(ctx, req)
	if err != nil {
		return dnsmessage.Message{}, fmt.Errorf("%s do raw dns request failed: %w", d.name, err)
	}

	return msg, nil
}

func (d *dnsWrap) Close() error {
	if d.dns != nil {
		return d.dns.Close()
	}

	return nil
}

func newDNS(name string, ipv6 bool, dc *pd.Dns, dialer netapi.Proxy) (netapi.Resolver, error) {
	subnet, err := netip.ParsePrefix(dc.Subnet)
	if err != nil {
		p, err := netip.ParseAddr(dc.Subnet)
		if err == nil {
			subnet = netip.PrefixFrom(p, p.BitLen())
		}
	}
	return dns.New(
		dns.Config{
			Type:       dc.Type,
			Name:       name,
			Host:       dc.Host,
			Servername: dc.TlsServername,
			Subnet:     subnet,
			IPv6:       ipv6,
			Dialer:     dialer,
		})
}

type dialer struct {
	netapi.Proxy
	addr func(ctx context.Context, addr netapi.Address)
}

func (d *dialer) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	ctx = netapi.NewStore(ctx)
	d.addr(ctx, addr)
	return d.Proxy.Conn(ctx, addr)
}

func (d *dialer) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	ctx = netapi.NewStore(ctx)
	d.addr(ctx, addr)
	return d.Proxy.PacketConn(ctx, addr)
}
