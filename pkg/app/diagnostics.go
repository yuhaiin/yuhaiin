package app

import (
	"context"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	"github.com/Asutorufa/yuhaiin/pkg/diagnostics"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
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
		TCP: func(ctx context.Context) []contracttools.TCPStackDiagnostic {
			if ctx.Err() != nil {
				return nil
			}
			var results []contracttools.TCPStackDiagnostic
			for _, inbound := range inbounds.TCPStackDiagnostics(32) {
				results = append(results, stackDiagnostic("inbound", inbound.InboundID, inbound.Snapshot))
			}
			for _, outbound := range nodeRuntime.ActiveTCPStackSnapshots(32) {
				results = append(results, stackDiagnostic("outbound", outbound.NodeID, outbound.Snapshot))
			}
			return results
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


// stackDiagnostic adapts the shared protocol stack's in-memory counters to the
// diagnostics contract. The scope specifies which layer owns these counters:
// the same payload may cross an inbound and an outbound, so only like-scope,
// non-overlapping stacks should be compared (never summed as global traffic).
func stackDiagnostic(scope, id string, stack lightweight.StackDiagnostics) contracttools.TCPStackDiagnostic {
	stats := stack.Stats
	report := contracttools.TCPStackDiagnostic{
		Scope: scope,
		MTU: stack.MTU,
		Statistics: contracttools.TCPStackStatistics{
			Connections: stats.Connections, MemoryBytes: stats.MemoryBytes,
			PacketsIn: stats.PacketsIn, PacketsOut: stats.PacketsOut,
			Drops: stats.Drops, Retransmissions: stats.Retransmissions,
			RSTSent: stats.RSTSent, RSTReceived: stats.RSTReceived,
			InvalidInputDrops: stats.InvalidInputDrops, RateLimitedDrops: stats.RateLimitedDrops,
			OutputAQMDrops: stats.OutputAQMDrops, OutputRejected: stats.OutputRejected,
			OutputOverloadDrops: stats.OutputOverloadDrops,
			OutputQueuedPackets: stats.OutputQueuedPackets, OutputQueuedBytes: stats.OutputQueuedBytes,
		},
		Flows: make([]contracttools.TCPFlowDiagnostic, 0, len(stack.Flows)),
	}
	if scope == "outbound" {
		report.NodeID = id
	} else {
		report.InboundID = id
	}
	for _, flow := range stack.Flows {
		item := contracttools.TCPFlowDiagnostic{
			State: string(flow.State), Local: flow.Local, Remote: flow.Remote,
			CongestionWindow: flow.CongestionWindow, BytesInFlight: flow.BytesInFlight,
			SRTTMilliseconds: flow.SRTTMilliseconds, RTOMilliseconds: flow.RTOMilliseconds,
			PacingRate: flow.PacingRate, LostBytes: flow.LostBytes,
			Retransmissions: flow.Retransmissions, DuplicateACKs: flow.DuplicateACKs,
			PathMSS: flow.PathMSS, Retries: flow.Retries, Recovering: flow.Recovering,
		}
		if flow.BBR != nil {
			item.BBRMode = string(flow.BBR.Mode)
			item.BBRPhase = string(flow.BBR.Phase)
		}
		report.Flows = append(report.Flows, item)
	}
	return report
}
