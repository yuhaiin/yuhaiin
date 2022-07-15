package statistic

import (
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

type resolvers struct {
	remotedns *remotedns
	localdns  *localdns
	bootstrap *bootstrap
}

func newResolvers(direct, proxy proxy.Proxy, counter *counter) *resolvers {
	c := &resolvers{}
	c.localdns = newLocaldns(counter)
	c.bootstrap = newBootstrap(counter)
	resolver.Bootstrap = c.bootstrap
	c.remotedns = newRemotedns(direct, proxy, counter)
	return c
}

func (r *resolvers) Update(s *protoconfig.Setting) {
	r.localdns.Update(s)
	r.bootstrap.Update(s)
	r.remotedns.Update(s)
}

func (r *resolvers) Close() error {
	if r.localdns != nil {
		r.localdns.Close()
	}

	if r.remotedns != nil {
		r.remotedns.Close()
	}
	if r.bootstrap != nil {
		r.bootstrap.Close()
	}

	return nil
}

type basedns struct {
	config *protoconfig.Dns
	dns    idns.DNS
	conns  conns
}

func (l *basedns) Update(c *protoconfig.Setting) {}
func (l *basedns) LookupIP(host string) (idns.IPResponse, error) {
	if l.dns == nil {
		return nil, fmt.Errorf("dns not initialized")
	}

	ips, err := l.dns.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("localdns lookup failed: %w", err)
	}

	return ips, nil
}
func (l *basedns) Close() error {
	if l.dns != nil {
		return l.dns.Close()
	}

	return nil
}
func (b *basedns) Do(r []byte) ([]byte, error) {
	if b.dns == nil {
		return nil, fmt.Errorf("bootstrap dns not initialized")
	}

	return b.dns.Do(r)
}

type remotedns struct {
	basedns
	direct, proxy proxy.Proxy
}

func newRemotedns(direct, proxy proxy.Proxy, conns conns) *remotedns {
	return &remotedns{basedns{conns: conns}, direct, proxy}
}
func (r *remotedns) Update(c *protoconfig.Setting) {
	if proto.Equal(r.config, c.Dns.Remote) {
		return
	}

	r.config = c.Dns.Remote
	if r.dns != nil {
		r.dns.Close()
	}

	var mark string
	var dialer proxy.Proxy
	if r.config.Proxy {
		mark = "REMOTEDNS_PROXY"
		dialer = r.proxy
	} else {
		mark = "REMOTEDNS_DIRECT"
		dialer = r.direct
	}

	r.dns = getDNS("REMOTEDNS", r.config, &dnsdialer{r.conns, dialer, mark})
}

type localdns struct{ basedns }

func newLocaldns(conns conns) *localdns { return &localdns{basedns: basedns{conns: conns}} }
func (l *localdns) Update(c *protoconfig.Setting) {
	if proto.Equal(l.config, c.Dns.Local) {
		return
	}

	l.config = c.Dns.Local
	l.Close()
	l.dns = getDNS("LOCALDNS", l.config, &dnsdialer{l.conns, direct.Default, "LOCALDNS_DIRECT"})
}

type bootstrap struct{ basedns }

func newBootstrap(conns conns) *bootstrap { return &bootstrap{basedns: basedns{conns: conns}} }
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
	b.dns = getDNS("BOOTSTRAP", b.config, &dnsdialer{b.conns, direct.Default, "BOOTSTRAP_DIRECT"})
}

func getDNS(name string, dc *protoconfig.Dns, proxy proxy.Proxy) idns.DNS {
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
		dc.Type,
		idns.Config{
			Name:       name,
			Host:       dc.Host,
			Servername: dc.TlsServername,
			Subnet:     subnet,
		},
		proxy)
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
