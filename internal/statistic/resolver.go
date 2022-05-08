package statistic

import (
	"context"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

type remotedns struct {
	config        *protoconfig.Dns
	dns           dns.DNS
	direct, proxy proxy.Proxy
	conns         conns
}

func newRemotedns(direct, proxy proxy.Proxy, conns conns) *remotedns {
	return &remotedns{
		direct: direct,
		proxy:  proxy,
		conns:  conns,
	}
}

func (r *remotedns) Update(c *protoconfig.Setting) {
	if proto.Equal(r.config, c.Dns.Remote) {
		return
	}

	r.config = c.Dns.Remote
	if r.dns != nil {
		r.dns.Close()
	}

	MODE := DIRECT
	dialer := r.direct
	if r.config.Proxy {
		MODE = PROXY
		dialer = r.proxy
	}
	r.dns = getDNS(r.config, &remotednsDialer{r.conns, dialer, MODE})
}

func (r *remotedns) LookupIP(host string) ([]net.IP, error) {
	if r.dns == nil {
		return nil, fmt.Errorf("dns not initialized")
	}
	return r.dns.LookupIP(host)
}

func (l *remotedns) Resolver() *net.Resolver {
	if l.dns == nil {
		return net.DefaultResolver
	}
	return l.dns.Resolver()
}

func (l *remotedns) Close() error {
	if l.dns != nil {
		return l.dns.Close()
	}
	return nil
}

type remotednsDialer struct {
	conns
	dialer proxy.Proxy
	MODE
}

func (c *remotednsDialer) Conn(host string) (net.Conn, error) {
	con, err := c.dialer.Conn(host)
	if err != nil {
		return nil, err
	}

	return c.conns.AddConn(con, host, c.MODE), nil
}

func (c *remotednsDialer) PacketConn(host string) (net.PacketConn, error) {
	con, err := c.dialer.PacketConn(host)
	if err != nil {
		return nil, err
	}

	return c.conns.AddPacketConn(con, host, c.MODE), nil
}

type localdns struct {
	config   *protoconfig.Dns
	dns      dns.DNS
	resolver *net.Resolver
	conns    conns
}

func newLocaldns(conns conns) *localdns {
	return &localdns{conns: conns}
}

func (l *localdns) Update(c *protoconfig.Setting) {
	if proto.Equal(l.config, c.Dns.Local) {
		return
	}

	l.config = c.Dns.Local
	l.Close()
	l.dns = getDNS(l.config, &localdnsDialer{l.conns})
	l.resolver = l.dns.Resolver()
}

func (l *localdns) LookupIP(host string) ([]net.IP, error) {
	if l.dns == nil {
		return net.DefaultResolver.LookupIP(context.TODO(), "ip", host)
	}

	return l.dns.LookupIP(host)
}

func (l *localdns) Resolver() *net.Resolver {
	if l.resolver == nil {
		return net.DefaultResolver
	}
	return l.resolver
}

func (l *localdns) Close() error {
	if l.dns != nil {
		return l.dns.Close()
	}

	return nil
}

type localdnsDialer struct{ conns }

func (d *localdnsDialer) Conn(host string) (net.Conn, error) {
	conn, err := direct.Default.Conn(host)
	if err != nil {
		return nil, err
	}

	return d.AddConn(conn, host, DIRECT), nil
}

func (d *localdnsDialer) PacketConn(host string) (net.PacketConn, error) {
	con, err := direct.Default.PacketConn(host)
	if err != nil {
		return nil, err
	}

	return d.AddPacketConn(con, host, DIRECT), nil
}

func getDNS(dc *protoconfig.Dns, proxy proxy.Proxy) dns.DNS {
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

	switch dc.Type {
	case protoconfig.Dns_doh:
		return dns.NewDoH(dc.Host, subnet, proxy)
	case protoconfig.Dns_dot:
		return dns.NewDoT(dc.Host, subnet, proxy)
	case protoconfig.Dns_doq:
		return dns.NewDoQ(dc.Host, subnet, proxy)
	case protoconfig.Dns_doh3:
		return dns.NewDoH3(dc.Host, subnet)
	case protoconfig.Dns_tcp:
		fallthrough
	case protoconfig.Dns_udp:
		fallthrough
	default:
		return dns.NewDNS(dc.Host, subnet, proxy)
	}
}
