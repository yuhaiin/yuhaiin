package sysnet

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/forward"
)

// MaxViewRoutes bounds the routes returned by SystemRoutes.
const MaxViewRoutes = 5000

const yuhaiinTable = 63

// SystemRoutes reads the operating system routing table and marks the routes
// Yuhaiin owns with the rule they come from. Where apps cannot read the table
// (Android), it lists the routes passed to the platform VPN instead.
func (m *Manager) SystemRoutes(context.Context) sysnet.SystemRoutes {
	out := sysnet.SystemRoutes{Platform: m.opts.Capabilities.Platform, Routes: []sysnet.SystemRouteEntry{}, Rules: []sysnet.SystemPolicyRule{}}
	entries, rules, err := m.opts.ListRoutes()
	ifaces, _ := m.opts.Interfaces()
	names := map[int]string{}
	for _, i := range ifaces {
		names[i.Index] = i.Name
	}

	m.mu.Lock()
	owned := m.owned
	platform := map[string][]netip.Prefix{}
	maps.Copy(platform, m.platformRoutes)
	platformRule := m.platformRule
	ruleNames := map[string]string{}
	for _, r := range m.config.Routes {
		ruleNames[r.ID] = r.Name
	}
	for _, r := range m.config.Forwarding.Rules {
		ruleNames[r.ID] = r.Name
	}
	tunNames := map[string]string{}
	for id, t := range m.tuns {
		tunNames[id] = t.InboundName
		if t.Interface != "" && t.Index > 0 {
			names[t.Index] = t.Interface
		}
	}
	tables := m.forwardTables
	m.mu.Unlock()

	name := func(source, id string) string {
		if source == sysnet.SourceRequired {
			return tunNames[id]
		}
		return ruleNames[id]
	}
	platformOwner := platformRule
	if err != nil && len(platform) != 0 && !errors.Is(err, netlink.ErrRouteListUnsupported) && m.opts.Capabilities.Platform == "android" {
		// An app without the routes host call: show what the VPN received.
		err = netlink.ErrRouteListUnsupported
	}
	if errors.Is(err, netlink.ErrRouteListUnsupported) {
		for _, routes := range platform {
			for _, p := range routes {
				id := platformRule[p]
				out.Routes = append(out.Routes, sysnet.SystemRouteEntry{Destination: p.String(), Interface: "VPN", Yuhaiin: true, Source: sysnet.SourceVPN, RuleID: id, RuleName: ruleNames[id]})
			}
		}
		out.Total, out.YuhaiinRoutes = len(out.Routes), len(out.Routes)
		sortRoutes(out.Routes)
		return out
	}
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Readable = true
	for _, e := range entries {
		v := sysnet.SystemRouteEntry{Destination: e.Destination.String(), InterfaceIndex: e.Link, Interface: cmp.Or(names[e.Link], e.Interface), Table: e.Table, Metric: e.Metric, Type: e.Type}
		if e.Gateway.IsValid() {
			v.Gateway = e.Gateway.String()
		}
		if e.OwnVPN {
			// Android: every route of this app's VPN network is Yuhaiin's; the
			// rule routes are known, the rest are the TUN subnets and FakeIP pools.
			v.Yuhaiin, v.Source = true, sysnet.SourceRequired
			if id, ok := platformOwner[e.Destination]; ok {
				v.Source, v.RuleID = sysnet.SourceVPN, id
			}
		} else if o, ok := owned[e.Destination]; ok && o.link == e.Link && (e.Table == 0 || e.Table == yuhaiinTable) {
			v.Yuhaiin, v.Source, v.RuleID = true, o.source, o.ruleID
		} else if o, ok := clonedFrom(owned, e); ok {
			// macOS clones a host route per destination from a TUN route.
			v.Yuhaiin, v.Source, v.RuleID = true, o.source, o.ruleID
		} else if e.Protocol == netlink.RouteProtocolYuhaiin {
			v.Yuhaiin, v.Source = true, sysnet.SourceStale
			if id, ok := tables[e.Table]; ok || e.Table == forward.TProxyTable {
				v.Source, v.RuleID = sysnet.SourceForwarding, id
			}
		}
		if v.Yuhaiin {
			v.RuleName = name(v.Source, v.RuleID)
			out.YuhaiinRoutes++
		}
		out.Routes = append(out.Routes, v)
	}
	out.Total = len(out.Routes)
	sortRoutes(out.Routes)
	if len(out.Routes) > MaxViewRoutes {
		out.Routes, out.Truncated = out.Routes[:MaxViewRoutes], true
	}
	for _, r := range rules {
		out.Rules = append(out.Rules, sysnet.SystemPolicyRule{Priority: r.Priority, Family: r.Family, Selector: r.Selector, Table: r.Table,
			Yuhaiin: r.Protocol == netlink.RouteProtocolYuhaiin || (r.Table == yuhaiinTable && (r.Priority == 30001 || r.Priority == 30002))})
	}
	slices.SortStableFunc(out.Rules, func(a, b sysnet.SystemPolicyRule) int {
		return cmp.Or(cmp.Compare(a.Family, b.Family), cmp.Compare(a.Priority, b.Priority))
	})
	return out
}

// clonedFrom returns the most specific owned route a kernel-cloned host
// route was derived from: one on the same link that contains it.
func clonedFrom(owned map[netip.Prefix]ownedRoute, e netlink.RouteEntry) (ownedRoute, bool) {
	if !e.Cloned {
		return ownedRoute{}, false
	}
	var best ownedRoute
	bits := -1
	for p, o := range owned {
		if o.link == e.Link && p.Bits() > bits && p.Bits() <= e.Destination.Bits() && p.Contains(e.Destination.Addr()) {
			best, bits = o, p.Bits()
		}
	}
	return best, bits >= 0
}

// sortRoutes orders by table, family, then prefix: the default routes and
// broad prefixes first.
func sortRoutes(routes []sysnet.SystemRouteEntry) {
	key := func(r sysnet.SystemRouteEntry) netip.Prefix { p, _ := netip.ParsePrefix(r.Destination); return p }
	slices.SortStableFunc(routes, func(a, b sysnet.SystemRouteEntry) int {
		pa, pb := key(a), key(b)
		return cmp.Or(cmp.Compare(a.Table, b.Table), cmp.Compare(boolInt(pa.Addr().Is6()), boolInt(pb.Addr().Is6())),
			pa.Addr().Compare(pb.Addr()), cmp.Compare(pa.Bits(), pb.Bits()))
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
