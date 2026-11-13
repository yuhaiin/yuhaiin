package inbound

import (
	"net/netip"
	"slices"
	"sync"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/platformvpn"
)

// contractReconfigurer is implemented by servers that can apply a changed
// inbound configuration without being closed and recreated.
type contractReconfigurer interface {
	ReconfigureContract(contract.Inbound) (handled bool, err error)
}

// platformTunManager and platformTunOpen are replaced in tests.
var (
	platformTunManager = platformvpn.Default
	platformTunOpen    = func(o device.TunConfig, handler netapi.Handler) (netapi.Accepter, error) {
		return tun.NewTun(o, nil, handler)
	}
)

// listenPlatformTun starts a TUN inbound whose device is created on demand by
// the host platform (Android VpnService). The core keeps running when the
// platform refuses the interface; the error becomes the inbound runtime state.
// Its routes come from System Network rules; the first interface already
// carries them.
func listenPlatformTun(config contract.Inbound, handler netapi.Handler, ranges [2]netip.Prefix) (netapi.Accepter, error) {
	p := &platformTunAccepter{id: config.ID}
	if wrap, ok := handler.(*handlerWrap); ok {
		p.routes, p.managed = wrap.handler.platformRoutes(config.ID)
	}
	open := func(o device.TunConfig) (netapi.Accepter, error) { return platformTunOpen(o, handler) }
	a, err := platformTunManager.New(config.ID, p.spec(*config.Protocol.Tun), ranges, open)
	if err != nil {
		return nil, err
	}
	p.Accepter = a
	return p, nil
}

func platformSpec(c contract.TunProtocol, routes []string, managed bool) platformvpn.Spec {
	spec := platformvpn.Spec{Stack: tunConfig(c), Routes: slices.Clone(routes), AutoFakeIPRoute: c.AutoFakeIPRoute}
	if managed {
		spec.RouteMode = platformvpn.RouteModeSystemNetwork
	}
	return spec
}

type platformTunAccepter struct {
	*platformvpn.Accepter
	id string

	mu      sync.Mutex
	routes  []string
	managed bool
}

func (p *platformTunAccepter) spec(c contract.TunProtocol) platformvpn.Spec {
	p.mu.Lock()
	defer p.mu.Unlock()
	return platformSpec(c, p.routes, p.managed)
}

// setRoutes receives the routes System Network rules give this TUN.
func (p *platformTunAccepter) setRoutes(routes []netip.Prefix, managed bool) error {
	p.mu.Lock()
	p.routes, p.managed = prefixStrings(routes), managed
	routesCopy := slices.Clone(p.routes)
	p.mu.Unlock()
	return p.SetRoutes(routesCopy, managed)
}

func (p *platformTunAccepter) ReconfigureContract(req contract.Inbound) (bool, error) {
	if req.ID != p.id || req.Protocol.Type != contract.ProtocolTun || req.Protocol.Tun == nil ||
		!platformvpn.IsDevice(req.Protocol.Tun.Name) || p.Generation() == 0 {
		// Revoked or failed interfaces are recreated from scratch.
		return false, nil
	}
	if err := req.Validate(); err != nil {
		return true, err
	}
	return true, p.Reconfigure(p.spec(*req.Protocol.Tun))
}
