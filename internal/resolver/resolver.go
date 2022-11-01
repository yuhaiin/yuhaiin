package resolver

import (
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/internal/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	idns "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/resolver"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"
)

type Resolvers struct {
	local, remote, bootstrap *basedns
}

func NewResolvers(dl proxy.Proxy) *Resolvers {
	resolver.Bootstrap = newResolver((&bootstrap{dl}).create)

	dialer := &dialer{Proxy: dl, Addr: func(addr proxy.Address) {
		// force to use bootstrap dns, otherwise will dns query cycle
		addr.WithResolver(resolver.Bootstrap, false)
	}}

	c := &Resolvers{
		remote:    newResolver((&remote{dialer}).create),
		local:     newResolver((&local{dialer}).create),
		bootstrap: resolver.Bootstrap.(*basedns),
	}

	return c
}

type bootstrap struct{ proxy.Proxy }

func (bs *bootstrap) create(b *basedns, c *protoconfig.Setting) {
	if proto.Equal(b.config, c.Dns.Bootstrap) {
		return
	}

	if err := config.CheckBootstrapDns(c.Dns.Bootstrap); err != nil {
		log.Errorln("check bootstrap dns failed: %v\n", err)
		return
	}

	b.config = c.Dns.Bootstrap
	b.Close()

	b.dns = getDNS("BOOTSTRAP", c.GetIpv6(), b.config, &dialer{Proxy: bs.Proxy, Addr: func(addr proxy.Address) {
		addr.WithValue(shunt.ForceModeKey{}, bypass.Mode_direct)
		addr.WithResolver(&resolver.System{DisableIPv6: !c.GetIpv6()}, false)
	}})
}

type remote struct{ proxy.Proxy }

func (re *remote) create(r *basedns, c *protoconfig.Setting) {
	if proto.Equal(r.config, c.Dns.Remote) {
		return
	}

	r.config = c.Dns.Remote
	r.Close()
	r.dns = getDNS("REMOTEDNS", c.GetIpv6(), r.config, re.Proxy)
}

type local struct{ proxy.Proxy }

func (lc *local) create(l *basedns, c *protoconfig.Setting) {
	if proto.Equal(l.config, c.Dns.Local) {
		return
	}

	l.config = c.Dns.Local
	l.Close()
	l.dns = getDNS("LOCALDNS", c.GetIpv6(), l.config, lc.Proxy)
}

func (r *Resolvers) Update(s *protoconfig.Setting) {
	r.local.Update(s)
	r.remote.Update(s)
	r.bootstrap.Update(s)
}

func (r *Resolvers) Close() error {
	r.local.Close()
	r.remote.Close()
	r.bootstrap.Close()
	return nil
}
func (r *Resolvers) Remote() idns.DNS { return r.remote }
func (r *Resolvers) Local() idns.DNS  { return r.local }

type basedns struct {
	config *pdns.Dns
	dns    idns.DNS

	update func(*basedns, *protoconfig.Setting)
}

func newResolver(update func(*basedns, *protoconfig.Setting)) *basedns {
	return &basedns{update: update}
}

func (l *basedns) Update(c *protoconfig.Setting) { l.update(l, c) }

func (l *basedns) LookupIP(host string) ([]net.IP, error) {
	if l.dns == nil {
		return nil, fmt.Errorf("dns not initialized")
	}

	ips, err := l.dns.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("localdns lookup failed: %w", err)
	}

	return ips, nil
}
func (l *basedns) Record(domain string, t dnsmessage.Type) (idns.IPResponse, error) {
	if l.dns == nil {
		return nil, fmt.Errorf("dns not initialized")
	}

	return l.dns.Record(domain, t)
}

func (l *basedns) Close() error {
	if l.dns != nil {
		return l.dns.Close()
	}

	return nil
}
func (b *basedns) Do(r []byte) ([]byte, error) {
	if b.dns == nil {
		return nil, fmt.Errorf("dns not initialized")
	}

	return b.dns.Do(r)
}

func getDNS(name string, ipv6 bool, dc *pdns.Dns, dialer proxy.Proxy) idns.DNS {
	_, subnet, err := net.ParseCIDR(dc.Subnet)
	if err != nil {
		p := net.ParseIP(dc.Subnet)
		if p != nil { // no mask
			var mask net.IPMask
			if p.To4() == nil { // ipv6
				mask = net.IPMask{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
			} else {
				mask = net.IPMask{255, 255, 255, 255}
			}

			subnet = &net.IPNet{IP: p, Mask: mask}
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
	Addr func(addr proxy.Address)
}

func (d *dialer) Conn(addr proxy.Address) (net.Conn, error) {
	d.Addr(addr)
	return d.Proxy.Conn(addr)
}

func (d *dialer) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	d.Addr(addr)
	return d.Proxy.PacketConn(addr)
}
