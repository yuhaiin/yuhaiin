package resolver

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/internal/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/app/config"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	id "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/resolver"
	pc "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"
)

type Resolvers struct{ Local, Remote, Bootstrap *client }

func NewResolvers(dl proxy.Proxy) *Resolvers {
	bootstrap := newClient(bootstrapUpdate(dl))

	dialer := &dialer{
		Proxy: dl,
		addr: func(addr proxy.Address) {
			// force to use bootstrap dns, otherwise will dns query cycle
			addr.WithResolver(bootstrap, false)
		},
	}

	c := &Resolvers{
		Remote:    newClient(remoteUpdate(dialer)),
		Local:     newClient(localUpdate(dialer)),
		Bootstrap: bootstrap,
	}

	resolver.Bootstrap = bootstrap

	return c
}

func (r *Resolvers) Update(s *pc.Setting) {
	r.Local.Update(s)
	r.Remote.Update(s)
	r.Bootstrap.Update(s)
}

func (r *Resolvers) Close() error {
	r.Local.Close()
	r.Remote.Close()
	r.Bootstrap.Close()
	return nil
}

func bootstrapUpdate(p proxy.Proxy) func(b *client, s *pc.Setting) {
	return func(b *client, c *pc.Setting) {
		if proto.Equal(b.config, c.Dns.Bootstrap) {
			return
		}

		if err := config.CheckBootstrapDns(c.Dns.Bootstrap); err != nil {
			log.Error("check bootstrap dns failed", "err", err)
			return
		}

		b.config = c.Dns.Bootstrap
		b.Close()

		z, err := getDNS("BOOTSTRAP", c.GetIpv6(), b.config,
			&dialer{
				Proxy: p,
				addr: func(addr proxy.Address) {
					addr.WithValue(shunt.ForceModeKey{}, bypass.Mode_direct)
					addr.WithResolver(&resolver.System{DisableIPv6: !c.GetIpv6()}, false)
				}},
		)
		if err != nil {
			log.Error("get bootstrap dns failed", "err", err)
		} else {
			b.dns = z
		}
	}
}

func remoteUpdate(p proxy.Proxy) func(b *client, s *pc.Setting) {
	return func(r *client, c *pc.Setting) {
		if proto.Equal(r.config, c.Dns.Remote) {
			return
		}

		r.config = c.Dns.Remote
		r.Close()
		z, err := getDNS("REMOTEDNS", c.GetIpv6(), r.config, p)
		if err != nil {
			log.Error("get remote dns failed", "err", err)
		} else {
			r.dns = z
		}
	}
}

func localUpdate(p proxy.Proxy) func(b *client, s *pc.Setting) {
	return func(l *client, c *pc.Setting) {

		if proto.Equal(l.config, c.Dns.Local) {
			return
		}

		l.config = c.Dns.Local
		l.Close()
		z, err := getDNS("LOCALDNS", c.GetIpv6(), l.config, p)
		if err != nil {
			log.Error("get local dns failed", "err", err)
		} else {
			l.dns = z
		}
	}
}

type client struct {
	config *pd.Dns
	dns    id.DNS

	update func(*client, *pc.Setting)
}

func newClient(update func(*client, *pc.Setting)) *client {
	return &client{update: update}
}

func (l *client) Update(c *pc.Setting) { l.update(l, c) }

func (l *client) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if l.dns == nil {
		return nil, fmt.Errorf("dns not initialized")
	}

	ips, err := l.dns.LookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("localdns lookup failed: %w", err)
	}

	return ips, nil
}
func (l *client) Record(ctx context.Context, domain string, t dnsmessage.Type) ([]net.IP, uint32, error) {
	if l.dns == nil {
		return nil, 0, fmt.Errorf("dns not initialized")
	}

	return l.dns.Record(ctx, domain, t)
}

func (l *client) Close() error {
	if l.dns != nil {
		return l.dns.Close()
	}

	return nil
}

func (b *client) Do(ctx context.Context, addr string, r []byte) ([]byte, error) {
	if b.dns == nil {
		return nil, fmt.Errorf("dns not initialized")
	}

	return b.dns.Do(ctx, addr, r)
}

func getDNS(name string, ipv6 bool, dc *pd.Dns, dialer proxy.Proxy) (id.DNS, error) {
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
	proxy.Proxy
	addr func(addr proxy.Address)
}

func (d *dialer) Conn(ctx context.Context, addr proxy.Address) (net.Conn, error) {
	d.addr(addr)
	return d.Proxy.Conn(ctx, addr)
}

func (d *dialer) PacketConn(ctx context.Context, addr proxy.Address) (net.PacketConn, error) {
	d.addr(addr)
	return d.Proxy.PacketConn(ctx, addr)
}
