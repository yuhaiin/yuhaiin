package statistic

import (
	"errors"
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	idns "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/statistic"
)

type router struct {
	remotedns *remotedns
	localdns  *localdns
	bootstrap *bootstrap
	statistic *counter
	shunt     *shunt

	dnsserver     server.DNSServer
	dnsserverHost string

	fake *fakedns
}

func NewRouter(dialer proxy.Proxy, fakednsIpRange *net.IPNet) *router {
	c := &router{statistic: NewStatistic()}

	c.localdns = newLocaldns(c.statistic)
	c.bootstrap = newBootstrap(c.statistic)
	resolver.Bootstrap = c.bootstrap
	c.remotedns = newRemotedns(direct.Default, dialer, c.statistic)

	c.shunt = newShunt(c.remotedns, c.statistic)

	c.shunt.AddDialer(PROXY, dialer, c.remotedns)
	c.shunt.AddDialer(DIRECT, direct.Default, c.localdns)
	c.shunt.AddDialer(BLOCK, proxy.NewErrProxy(errors.New("block")), idns.NewErrorDNS(errors.New("block")))

	c.fake = newFakedns(fakednsIpRange, c.shunt)

	return c
}

func (a *router) Update(s *protoconfig.Setting) {
	a.shunt.Update(s)
	a.localdns.Update(s)
	a.bootstrap.Update(s)
	a.remotedns.Update(s)
	a.fake.Update(s)

	UpdateInterfaceName(s)

	if a.dnsserverHost == s.Dns.Server {
		return
	}

	if a.dnsserver != nil {
		if err := a.dnsserver.Close(); err != nil {
			log.Println("close dns server failed:", err)
		}
	}

	if s.Dns.Server != "" {
		a.dnsserver = dns.NewDnsServer(s.Dns.Server, a.fake.GetResolver)
	}

	a.dnsserverHost = s.Dns.Server
}

func (a *router) Proxy() proxy.Proxy          { return a.fake }
func (a *router) DNSServer() server.DNSServer { return a.dnsserver }

func (a *router) Insert(addr string, mode *MODE) {
	if a.shunt == nil {
		return
	}

	a.shunt.mapper.Insert(addr, mode)
}

func (a *router) Statistic() statistic.ConnectionsServer { return a.statistic }

func (a *router) Close() error {
	if a.dnsserver != nil {
		a.dnsserver.Close()
	}

	if a.localdns != nil {
		a.localdns.Close()
	}

	if a.remotedns != nil {
		a.remotedns.Close()
	}
	if a.bootstrap != nil {
		a.bootstrap.Close()
	}

	return nil
}

type fakedns struct {
	fake *dns.Fake

	config *protoconfig.DnsSetting

	shunt *shunt
}

func newFakedns(ipRange *net.IPNet, dialer *shunt) *fakedns {
	return &fakedns{
		fake:  dns.NewFake(ipRange),
		shunt: dialer,
	}
}

func (f *fakedns) GetResolver(addr proxy.Address) idns.DNS {
	z, mode := f.shunt.GetResolver(addr)
	if mode != BLOCK && f.config != nil && f.config.Fakedns {
		return dns.WrapFakeDNS(z, f.fake)
	}
	return z
}

func (f *fakedns) Update(c *protoconfig.Setting) { f.config = c.Dns }

func (f *fakedns) Conn(addr proxy.Address) (net.Conn, error) {
	return f.shunt.Conn(f.getAddr(addr))
}

func (f *fakedns) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	return f.shunt.PacketConn(f.getAddr(addr))
}

func (f *fakedns) getAddr(addr proxy.Address) proxy.Address {
	if f.config != nil && f.config.Fakedns && addr.Type() == proxy.IP {
		t, ok := f.fake.GetDomainFromIP(addr.Hostname())
		if ok {
			addr = proxy.ParseAddressSplit("tcp", t, addr.Port().Port())
		}
	}

	return addr
}

func UpdateInterfaceName(cb *protoconfig.Setting) { dialer.DefaultInterfaceName = cb.GetNetInterface() }
