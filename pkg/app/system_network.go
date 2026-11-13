package app

import (
	"context"
	"errors"
	"runtime"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractsysnet "github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/platformvpn"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/forward"
)

// newSystemNetwork creates the System Network Manager with this platform's
// route and forwarding adapters.
func newSystemNetwork(lists *route.Lists) *sysnet.Manager {
	opts := sysnet.Options{GeoIP: lists}
	routes, err := netlink.NewRouteManager()
	switch {
	case err == nil:
		opts.Routes = routes
	case !errors.Is(err, netlink.ErrRoutesUnsupported):
		log.Error("system route management unavailable", "err", err)
	}
	if forward.Supported() {
		opts.Forward = forward.New()
	}
	opts.Capabilities = sysnet.PlatformCapabilities(runtime.GOOS, opts.Routes != nil, opts.Forward != nil)
	m := sysnet.New(opts)
	lists.OnGeoIPChange(func() { m.Reconcile("GeoIP database updated") })
	m.StartMonitor()
	return m
}

// systemNetworkInbounds lists inbounds for the System Network editor.
type systemNetworkInbounds struct{ store *plainstore.InboundStore }

func (s systemNetworkInbounds) list(ctx context.Context) []contractinbound.Inbound {
	items, err := s.store.List(ctx)
	if err != nil {
		log.Warn("list inbounds for System Network failed", "err", err)
	}
	return items
}

func (s systemNetworkInbounds) TunInbounds(ctx context.Context) []contractsysnet.TunInbound {
	out := []contractsysnet.TunInbound{}
	for _, in := range s.list(ctx) {
		if in.Protocol.Type == contractinbound.ProtocolTun && in.Protocol.Tun != nil {
			out = append(out, contractsysnet.TunInbound{ID: in.ID, Name: in.Name, Platform: platformvpn.IsDevice(in.Protocol.Tun.Name)})
		}
	}
	return out
}

func (s systemNetworkInbounds) TProxyInbounds(ctx context.Context) []contractsysnet.TProxyInbound {
	out := []contractsysnet.TProxyInbound{}
	for _, in := range s.list(ctx) {
		if in.Protocol.Type != contractinbound.ProtocolTProxy || in.Protocol.TProxy == nil {
			continue
		}
		listen := in.Protocol.TProxy.Host
		if in.Network.TCPUDP != nil && in.Network.TCPUDP.Host != "" {
			listen = in.Network.TCPUDP.Host
		}
		out = append(out, contractsysnet.TProxyInbound{ID: in.ID, Name: in.Name, Listen: listen})
	}
	return out
}

func systemNetworkController(m *sysnet.Manager) httpapi.SystemNetworkController {
	if m == nil {
		return nil
	}
	return m
}
