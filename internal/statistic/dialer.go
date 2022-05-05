package statistic

import (
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type dialer struct {
	store syncmap.SyncMap[MODE, proxy.Proxy]

	localdns *localResolver
}

func newDialer(dia proxy.Proxy) *dialer {
	d := &dialer{localdns: newLocalResolver()}
	d.store.Store(PROXY, dia)
	d.store.Store(BLOCK, proxy.NewErrProxy(errors.New("blocked")))
	d.store.Store(DIRECT, direct.NewDirect(direct.WithLookup(d.localdns)))
	return d
}

func (d *dialer) Update(s *protoconfig.Setting) { d.localdns.Update(s) }

func (d *dialer) dial(m MODE) proxy.Proxy {
	p, ok := d.store.Load(m)
	if !ok {
		p, _ = d.store.Load(PROXY)
	}

	return p
}
