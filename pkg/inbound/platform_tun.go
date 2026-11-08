package inbound

import (
	"net/netip"

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
func listenPlatformTun(config contract.Inbound, handler netapi.Handler, ranges [2]netip.Prefix) (netapi.Accepter, error) {
	open := func(o device.TunConfig) (netapi.Accepter, error) { return platformTunOpen(o, handler) }
	a, err := platformTunManager.New(config.ID, platformSpec(*config.Protocol.Tun), ranges, open)
	if err != nil {
		return nil, err
	}
	return &platformTunAccepter{Accepter: a, id: config.ID}, nil
}

func platformSpec(c contract.TunProtocol) platformvpn.Spec {
	stack := tunConfig(c)
	// tunConfig merges excludes into Routes for desktop route managers; the
	// platform receives them separately.
	stack.Routes = nil
	return platformvpn.Spec{
		Stack:           stack,
		Routes:          append([]string(nil), c.Routes...),
		Excludes:        append([]string(nil), c.Excludes...),
		AutoFakeIPRoute: c.AutoFakeIPRoute,
	}
}

type platformTunAccepter struct {
	*platformvpn.Accepter
	id string
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
	return true, p.Reconfigure(platformSpec(*req.Protocol.Tun))
}
