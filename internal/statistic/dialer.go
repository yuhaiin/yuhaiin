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

	local *protoconfig.Dns
}

func newDialer(dia proxy.Proxy) *dialer {

	d := &dialer{}

	d.store.Store(PROXY, dia)
	d.store.Store(BLOCK, proxy.NewErrProxy(errors.New("blocked")))

	return d
}

func (d *dialer) Update(s *protoconfig.Setting) {
	if d.local != nil && !diffDNS(d.local, s.Dns.Local) {
		return
	}

	d.store.Store(DIRECT, direct.NewDirect(direct.WithLookup(getDNS(s.Dns.Local, nil).LookupIP)))
	d.local = s.Dns.Local
}

func (d *dialer) dial(m MODE) proxy.Proxy {
	p, ok := d.store.Load(m)
	if !ok {
		p, _ = d.store.Load(PROXY)
	}

	return p
}
