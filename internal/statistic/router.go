package statistic

import (
	"errors"
	"log"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
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
}

func NewRouter(dialer proxy.Proxy) *router {
	c := &router{statistic: NewStatistic()}

	c.localdns = newLocaldns(c.statistic)
	c.bootstrap = newBootstrap(c.statistic)
	resolver.Bootstrap = c.bootstrap
	c.remotedns = newRemotedns(direct.Default, dialer, c.statistic)

	c.shunt = newShunt(c.remotedns, c.statistic)
	c.shunt.AddDialer(PROXY, dialer, c.remotedns)
	c.shunt.AddDialer(DIRECT, direct.Default, c.localdns)
	c.shunt.AddDialer(BLOCK, proxy.NewErrProxy(errors.New("block")), c.localdns)

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
		a.dnsserver = dns.NewDnsServer(s.Dns.Server, a.shunt.GetResolver)
	}
	a.dnsserverHost = s.Dns.Server
}

func (a *router) Proxy() proxy.Proxy { return a.shunt }

func (a *router) Statistic() statistic.ConnectionsServer { return a.statistic }
