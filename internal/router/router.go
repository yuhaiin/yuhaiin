package router

import (
	"bufio"
	"errors"
	"io"
	"strings"

	stc "github.com/Asutorufa/yuhaiin/internal/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

type Router struct {
	shunt Shunt
	*dnsServer
	*fakedns
	modes []Mode
}

type Mode struct {
	Mode     protoconfig.BypassMode
	Default  bool
	Dialer   proxy.Proxy
	Resolver dns.DNS
	Rules    string
}

func NewRouter(statistics stc.Statistics, bypassResolver dns.DNS, modes []Mode) *Router {
	c := &Router{modes: modes}

	c.shunt = newShunt(bypassResolver, statistics)

	for _, mode := range modes {
		c.shunt.AddMode(mode.Mode.String(), mode.Default, mode.Dialer, mode.Resolver)
	}

	c.fakedns = newFakedns(c.shunt)
	c.dnsServer = newDNSServer(c.fakedns)

	return c
}

func (a *Router) Update(s *protoconfig.Setting) {
	a.shunt.Update(s)
	for _, mode := range a.modes {
		a.insert(mode.Rules, mode.Mode)
	}
	a.fakedns.Update(s)
	a.dnsServer.Update(s)
}

func (a *Router) insert(rules string, mode protoconfig.BypassMode) {
	r := bufio.NewReader(strings.NewReader(rules))
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			continue
		}

		a.shunt.Insert(string(line), mode.String())
	}
}
