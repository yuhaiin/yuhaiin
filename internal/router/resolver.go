package router

import (
	"fmt"
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/internal/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	idns "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/resolver"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/protobuf/proto"
)

type Resolvers struct {
	// 0: remote dns, 1: local dns, 2: bootstrap dns
	dns [3]*basedns
}

func NewResolvers(direc, prox proxy.Proxy, counter statistics.Statistics) *Resolvers {
	c := &Resolvers{
		dns: [3]*basedns{
			newBasedns(func(r *basedns, c *protoconfig.Setting) {
				if proto.Equal(r.config, c.Dns.Remote) {
					return
				}

				r.config = c.Dns.Remote
				r.Close()

				var mark string
				var dialer proxy.Proxy
				if r.config.Proxy {
					mark = "REMOTEDNS_PROXY"
					dialer = prox
				} else {
					mark = "REMOTEDNS_DIRECT"
					dialer = direc
				}

				r.dns = getDNS("REMOTEDNS",
					c.GetIpv6(),
					r.config,
					&dnsdialer{counter, dialer, mark},
				)
			}),
			newBasedns(func(l *basedns, c *protoconfig.Setting) {
				if proto.Equal(l.config, c.Dns.Local) {
					return
				}

				l.config = c.Dns.Local
				l.Close()
				l.dns = getDNS(
					"LOCALDNS",
					c.GetIpv6(),
					l.config,
					&dnsdialer{counter, direct.Default, "LOCALDNS_DIRECT"},
				)
			}),
			newBasedns(func(b *basedns, c *protoconfig.Setting) {
				if proto.Equal(b.config, c.Dns.Bootstrap) {
					return
				}

				if err := config.CheckBootstrapDns(c.Dns.Bootstrap); err != nil {
					log.Printf("check bootstrap dns failed: %v\n", err)
					return
				}

				b.config = c.Dns.Bootstrap
				b.Close()
				b.dns = getDNS(
					"BOOTSTRAP",
					c.GetIpv6(),
					b.config,
					&dnsdialer{counter, direct.Default, "BOOTSTRAP_DIRECT"},
				)
			}),
		},
	}

	resolver.Bootstrap = c.dns[2]
	return c
}

func (r *Resolvers) Update(s *protoconfig.Setting) {
	for _, d := range r.dns {
		d.Update(s)
	}
}

func (r *Resolvers) Close() error {
	for _, d := range r.dns {
		d.Close()
	}
	return nil
}
func (r *Resolvers) Remote() idns.DNS { return r.dns[0] }
func (r *Resolvers) Local() idns.DNS  { return r.dns[1] }

type basedns struct {
	config *protoconfig.Dns
	dns    idns.DNS

	update func(*basedns, *protoconfig.Setting)
}

func newBasedns(update func(*basedns, *protoconfig.Setting)) *basedns {
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

func getDNS(name string, ipv6 bool, dc *protoconfig.Dns, dialer proxy.Proxy) idns.DNS {
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

type dnsdialer struct {
	conns  statistics.Statistics
	dialer proxy.Proxy
	mark   string
}

func (c *dnsdialer) Conn(host proxy.Address) (net.Conn, error) {
	con, err := c.dialer.Conn(host)
	if err != nil {
		return nil, err
	}
	host.AddMark(MODE_MARK, c.mark)

	return c.conns.AddConn(con, host), nil
}

func (c *dnsdialer) PacketConn(host proxy.Address) (net.PacketConn, error) {
	con, err := c.dialer.PacketConn(host)
	if err != nil {
		return nil, err
	}
	host.AddMark(MODE_MARK, c.mark)
	return c.conns.AddPacketConn(con, host), nil
}
