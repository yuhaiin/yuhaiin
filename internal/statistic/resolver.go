package statistic

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	idns "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

type remotedns struct {
	config        *protoconfig.Dns
	dns           idns.DNS
	direct, proxy proxy.Proxy
	conns         conns
}

func newRemotedns(direct, proxy proxy.Proxy, conns conns) *remotedns {
	return &remotedns{direct: direct, proxy: proxy, conns: conns}
}

func (r *remotedns) Update(c *protoconfig.Setting) {
	if proto.Equal(r.config, c.Dns.Remote) {
		return
	}

	r.config = c.Dns.Remote
	if r.dns != nil {
		r.dns.Close()
	}

	mark := "REMOTEDNS_DIRECT"
	dialer := r.direct
	if r.config.Proxy {
		mark = "REMOTEDNS_PROXY"
		dialer = r.proxy
	}

	r.dns = getDNS(r.config, &dnsdialer{r.conns, dialer, mark})
}

func (r *remotedns) LookupIP(host string) ([]net.IP, error) {
	if r.dns == nil {
		return nil, fmt.Errorf("dns not initialized")
	}
	ips, err := r.dns.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("remotedns lookup failed: %w", err)
	}

	log.Println("remotedns lookup success:", host, ips)
	return ips, nil
}

func (l *remotedns) Close() error {
	if l.dns != nil {
		return l.dns.Close()
	}
	return nil
}

type localdns struct {
	config *protoconfig.Dns
	dns    idns.DNS
	conns  conns
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
	l.dns = getDNS(l.config, &dnsdialer{l.conns, direct.Default, "LOCALDNS_DIRECT"})
}

func (l *localdns) LookupIP(host string) ([]net.IP, error) {
	if l.dns == nil {
		return resolver.LookupIP(host)
	}

	ips, err := l.dns.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("localdns lookup failed: %w", err)
	}

	log.Println("localdns lookup success:", host, ips)
	return ips, nil
}

func (l *localdns) Close() error {
	if l.dns != nil {
		return l.dns.Close()
	}

	return nil
}

type bootstrap struct {
	config *protoconfig.Dns
	dns    idns.DNS
	conns  conns
}

func newBootstrap(conns conns) *bootstrap {
	return &bootstrap{conns: conns}
}

func (b *bootstrap) Update(c *protoconfig.Setting) {
	if proto.Equal(b.config, c.Dns.Bootstrap) {
		return
	}

	err := config.CheckBootstrapDns(c.Dns.Bootstrap)
	if err != nil {
		log.Printf("check bootstrap dns failed: %v\n", err)
		return
	}

	b.config = c.Dns.Bootstrap
	b.Close()
	b.dns = getDNS(b.config, &dnsdialer{b.conns, direct.Default, "BOOTSTRAP_DIRECT"})
}

func (l *bootstrap) LookupIP(host string) ([]net.IP, error) {
	if l.dns == nil {
		return net.DefaultResolver.LookupIP(context.TODO(), "ip", host)
	}

	ips, err := l.dns.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("localdns lookup failed: %w", err)
	}

	log.Println("bootstrap dns lookup success:", host, ips)
	return ips, nil
}

func (b *bootstrap) Close() error {
	if b.dns != nil {
		return b.dns.Close()
	}

	return nil
}

func getDNS(dc *protoconfig.Dns, proxy proxy.Proxy) idns.DNS {
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
		return dns.NewDoH(dc.Host, dc.TlsServername, subnet, proxy)
	case protoconfig.Dns_dot:
		return dns.NewDoT(dc.Host, dc.TlsServername, subnet, proxy)
	case protoconfig.Dns_doq:
		return dns.NewDoQ(dc.Host, dc.TlsServername, subnet, proxy)
	case protoconfig.Dns_doh3:
		return dns.NewDoH3(dc.Host, subnet)
	case protoconfig.Dns_tcp:
		return dns.NewTCP(dc.Host, subnet, proxy)
	case protoconfig.Dns_udp:
		fallthrough
	default:
		return dns.NewDoU(dc.Host, subnet, proxy)
	}
}

type dnsdialer struct {
	conns
	dialer proxy.Proxy
	mark   string
}

func (c *dnsdialer) Conn(host proxy.Address) (net.Conn, error) {
	con, err := c.dialer.Conn(host)
	if err != nil {
		return nil, err
	}

	return c.conns.AddConn(con, host, c.mark), nil
}

func (c *dnsdialer) PacketConn(host proxy.Address) (net.PacketConn, error) {
	con, err := c.dialer.PacketConn(host)
	if err != nil {
		return nil, err
	}

	return c.conns.AddPacketConn(con, host, c.mark), nil
}
