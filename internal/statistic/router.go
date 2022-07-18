package statistic

import (
	"errors"
	"fmt"
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
	c.shunt.AddMode(protoconfig.Bypass_proxy.String(), true, dialer, c.resolvers.remotedns)
	c.shunt.AddMode(protoconfig.Bypass_direct.String(), false, direct.Default, c.resolvers.localdns)
	c.shunt.AddMode(protoconfig.Bypass_block.String(), false, proxy.NewErrProxy(errors.New("BLOCKED")), idns.NewErrorDNS(errors.New("BLOCKED")))

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

func (a *router) Insert(addr string, mode string) {
	if a.shunt != nil {
		a.shunt.Insert(addr, mode)
	}
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
	block int64
}

func newFakedns(ipRange *net.IPNet, dialer *shunt) *fakedns {
	return &fakedns{
		fake:  dns.NewFake(ipRange),
		shunt: dialer,
		block: dialer.GetID(protoconfig.Bypass_block.String()),
	}
}

func (f *fakedns) GetResolver(addr proxy.Address) idns.DNS {
	z, m := f.shunt.GetResolver(addr)
	if m != f.block && f.config != nil && f.config.Fakedns {
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
	c, err := f.shunt.Conn(f.getAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("connect tcp to %s(%s) failed: %s", addr, getStringValue("packageName", addr), err)
	}

	return c, nil
}

func (f *fakedns) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	c, err := f.shunt.PacketConn(f.getAddr(addr))
	if err != nil {
		return nil, fmt.Errorf("connect udp to %s(%s) failed: %s", addr, getStringValue("packageName", addr), err)
	}
	return c, nil
}

const FAKEDNS_MARK = "FAKEDNS"

func (f *fakedns) getAddr(addr proxy.Address) proxy.Address {
	if f.config != nil && f.config.Fakedns && addr.Type() == proxy.IP {
		t, ok := f.fake.GetDomainFromIP(addr.Hostname())
		if ok {
			fakeip := addr.String()
			addr = proxy.ConvertFakeDNS(addr, t)
			addr.AddMark(FAKEDNS_MARK, fakeip)
		}
	}
	return addr
}
