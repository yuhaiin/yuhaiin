package statistic

import (
	"errors"
	"log"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	idns "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type router struct {
	remotedns *remotedns
	localdns  *localdns
	bootstrap *bootstrap
	statistic *counter
	shunt     *shunt

	dnsserver     server.Server
	dnsserverHost string

	fake *dns.Fake
}

func NewRouter(dialer proxy.Proxy, fakednsIpRange *net.IPNet) *router {
	c := &router{statistic: NewStatistic()}

	c.fake = dns.NewFake(fakednsIpRange)

	c.localdns = newLocaldns(c.statistic)
	c.bootstrap = newBootstrap(c.statistic)
	resolver.Bootstrap = c.bootstrap
	c.remotedns = newRemotedns(direct.Default, dialer, c.statistic)

	c.shunt = newShunt(c.remotedns, c.statistic, c.fake)

	c.shunt.AddDialer(PROXY, dialer, c.remotedns)
	c.shunt.AddDialer(DIRECT, direct.Default, c.localdns)
	c.shunt.AddDialer(BLOCK, proxy.NewErrProxy(errors.New("block")), idns.NewErrorDNS(errors.New("block")))

	return c
}

func (a *router) Update(s *protoconfig.Setting) {
	a.shunt.Update(s)
	a.localdns.Update(s)
	a.bootstrap.Update(s)
	a.remotedns.Update(s)

	if a.dnsserverHost == s.Dns.Server {
		return
	}

	if a.dnsserver != nil {
		if err := a.dnsserver.Close(); err != nil {
			log.Println("close dns server failed:", err)
		}
	}

	if s.Dns.Server != "" {
		f := a.shunt.GetResolver
		if s.Dns.Fakedns {
			f = func(addr proxy.Address) idns.DNS {
				r := a.shunt.GetResolver(addr)

				return dns.WrapFakeDNS(r, a.fake)
			}
		}
		a.dnsserver = dns.NewDnsServer(s.Dns.Server, f)
	}
	a.dnsserverHost = s.Dns.Server
}

func (a *router) Proxy() proxy.Proxy { return a.shunt }

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
