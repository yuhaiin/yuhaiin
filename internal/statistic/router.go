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
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/grpc/statistic"
)

type router struct {
	resolvers *resolvers
	statistic *counter
	shunt     *shunt
	dnsServer *dnsServer
}

func NewRouter(dialer proxy.Proxy) *router {
	c := &router{
		statistic: newStatistic(),
	}

	c.resolvers = newResolvers(direct.Default, dialer, c.statistic)

	c.shunt = newShunt(c.resolvers.remotedns, c.statistic)
	c.shunt.AddMode(PROXY, dialer, c.resolvers.remotedns)
	c.shunt.AddMode(DIRECT, direct.Default, c.resolvers.localdns)
	c.shunt.AddMode(BLOCK, proxy.DiscardProxy, idns.NewErrorDNS(errors.New("block")))

	c.dnsServer = newDNSServer(c.shunt)
	return c
}

func (a *router) Update(s *protoconfig.Setting) {
	a.shunt.Update(s)
	a.resolvers.Update(s)
	a.dnsServer.Update(s)
	UpdateInterfaceName(s)
}

func (a *router) Proxy() proxy.Proxy          { return a.dnsServer.fake }
func (a *router) DNSServer() server.DNSServer { return a.dnsServer.dnsserver }

func (a *router) Insert(addr string, mode *MODE) {
	if a.shunt == nil {
		return
	}

	a.shunt.mapper.Insert(addr, mode)
}

func (a *router) Statistic() statistic.ConnectionsServer { return a.statistic }

func (a *router) Close() error {
	if a.dnsServer != nil {
		a.dnsServer.Close()
	}
	if a.resolvers != nil {
		a.resolvers.Close()
	}
	if a.statistic != nil {
		a.statistic.CloseAll()
	}
	return nil
}

func UpdateInterfaceName(cb *protoconfig.Setting) { dialer.DefaultInterfaceName = cb.GetNetInterface() }

type dnsServer struct {
	dnsserver     server.DNSServer
	dnsserverHost string
	fake          *fakedns
}

func newDNSServer(shunt *shunt) *dnsServer {
	_, ipRange, _ := net.ParseCIDR("10.2.0.1/24")
	return &dnsServer{fake: newFakedns(ipRange, shunt)}
}

func (a *dnsServer) Update(s *protoconfig.Setting) {
	a.fake.Update(s)
	if a.dnsserverHost == s.Dns.Server && a.dnsserver != nil {
		return
	}

	if a.dnsserver != nil {
		if err := a.dnsserver.Close(); err != nil {
			log.Println("close dns server failed:", err)
		}
	}
	a.dnsserver = dns.NewDnsServer(s.Dns.Server, a.fake.GetResolver)
	a.dnsserverHost = s.Dns.Server
}

func (a *dnsServer) Close() error {
	if a.dnsserver != nil {
		return a.dnsserver.Close()
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
	z, _ := f.shunt.GetResolver(addr)
	if f.config != nil && f.config.Fakedns {
		return dns.WrapFakeDNS(z, f.fake)
	}
	return z
}

func (f *fakedns) Update(c *protoconfig.Setting) {
	f.config = c.Dns

	_, ipRange, err := net.ParseCIDR(c.Dns.FakednsIpRange)
	if err != nil {
		log.Println("parse fakedns ip range failed:", err)
		return
	}

	f.fake = dns.NewFake(ipRange)
}

func (f *fakedns) Conn(addr proxy.Address) (net.Conn, error) {
	return f.shunt.Conn(f.getAddr(addr))
}

func (f *fakedns) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	return f.shunt.PacketConn(f.getAddr(addr))
}

const FAKEDNS_MARK = "FAKEDNS"

func (f *fakedns) getAddr(addr proxy.Address) proxy.Address {
	if f.config != nil && f.config.Fakedns && addr.Type() == proxy.IP {
		t, ok := f.fake.GetDomainFromIP(addr.Hostname())
		if ok {
			ad := addr
			addr = proxy.ParseAddressSplit("tcp", t, addr.Port().Port())
			addr.AddMark(FAKEDNS_MARK, ad.String())
		}
	}

	return addr
}
