package app

import (
	"context"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/diagnostics"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/route"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func newDiagnostics(inboundConfigStore *plainstore.InboundStore, inbounds *inbound.Inbound, nodeRuntime *node.NodeRuntime, hosts *resolver.Hosts, rules *route.Rules) *diagnostics.Service {
	return diagnostics.New(diagnostics.Dependencies{
		IPv6Enabled: configuration.IPv6.Load,
		Direct:      direct.Default,
		Routed:      hosts,
		Route:       rules.TestContract,
		Lookup: func(ctx context.Context, host string, ipv6 bool) ([]string, error) {
			mode := netapi.ResolverModePreferIPv4
			if ipv6 {
				mode = netapi.ResolverModePreferIPv6
			}
			ips, err := hosts.LookupIP(ctx, host, func(o *netapi.LookupIPOption) { o.Mode = mode })
			if err != nil {
				return nil, err
			}
			var out []string
			if ips != nil {
				addresses := ips.A
				if ipv6 {
					addresses = ips.AAAA
				}
				for _, ip := range addresses {
					out = append(out, ip.String())
				}
			}
			return out, nil
		},
		SelectedProxy: func(ctx context.Context) (netapi.StreamProxy, error) {
			selected, err := nodeRuntime.Selected(ctx)
			if err != nil || selected.TCP == nil {
				return nil, err
			}
			return nodeRuntime.GetDialerByID(ctx, selected.TCP.ID)
		},
		TUN: func(ctx context.Context) ([]diagnostics.TUNState, error) {
			if inboundConfigStore == nil {
				return nil, errors.New("inbound store unavailable")
			}
			items, err := inboundConfigStore.List(ctx)
			if err != nil {
				return nil, err
			}
			var states []diagnostics.TUNState
			for _, item := range items {
				if item.Protocol.Type != contractinbound.ProtocolTun || item.Protocol.Tun == nil {
					continue
				}
				id := item.ID
				if id == "" {
					id = item.Name
				}
				registered, streams, packets, pings := inbounds.ListenerSnapshot(id)
				states = append(states, diagnostics.TUNState{Enabled: item.Enabled, Running: registered, Driver: item.Protocol.Tun.Driver, MTU: item.Protocol.Tun.MTU, Streams: streams, Packets: packets, Pings: pings})
			}
			return states, nil
		},
	})
}
