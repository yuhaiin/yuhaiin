package statistic

import (
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type router struct {
	remotedns *remotedns
	localdns  *localdns
	statistic *counter
	shunt     *shunt
}

func NewRouter(dialer proxy.Proxy) *router {
	c := &router{statistic: NewStatistic()}

	c.localdns = newLocaldns(c.statistic)

	direct := direct.NewDirect(direct.WithLookup(c.localdns))

	c.remotedns = newRemotedns(direct, dialer, c.statistic)

	c.shunt = newShunt(c.remotedns, c.statistic)
	c.shunt.AddDialer(PROXY, dialer)
	c.shunt.AddDialer(DIRECT, direct)
	c.shunt.AddDialer(BLOCK, proxy.NewErrProxy(errors.New("block")))

	return c
}

func (a *router) Update(s *protoconfig.Setting) {
	a.shunt.Update(s)
	a.localdns.Update(s)
	a.remotedns.Update(s)
}

func (a *router) Proxy() proxy.Proxy { return a.shunt }

func (a *router) Statistic() statistic.ConnectionsServer { return a.statistic }
