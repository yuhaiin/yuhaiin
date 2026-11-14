package sysnet

import (
	"context"
	"fmt"
	"net/netip"
	"runtime"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
)

// outboundSources are the inputs of the outbound routing view, replaceable in
// tests.
type outboundSources struct {
	goos         string
	protection   func() dialer.ProtectionReport
	ownTuns      func() []string
	configured   func() string
	selectRoute  func(netip.Addr, func(string) bool) (interfaces.RouteChoice, bool)
	defaults     func() []interfaces.RouteChoice
	rules        func() ([]netlink.ProtectionRule, error)
	mainViaTun   func([]int) ([]netip.Prefix, error)
	tableRoutes  func() int // routes installed in the TUN table
	interfaces   func() ([]iface.Info, error)
	scopedRoutes func() ([]netlink.ScopedRoute, error)
}

func (m *Manager) outboundSources() outboundSources {
	src := outboundSources{
		goos:       runtime.GOOS,
		protection: dialer.Protection,
		ownTuns: func() []string {
			var out []string
			dialer.SkipInterface().Range(func(s string) bool { out = append(out, s); return true })
			slices.Sort(out)
			return out
		},
		configured:  func() string { return dialer.ConfiguredInterface() },
		selectRoute: interfaces.SelectRoute,
		defaults:    interfaces.DefaultRoutes,
		rules:       netlink.ProtectionRules,
		mainViaTun:  netlink.MainRoutesVia,
		tableRoutes: func() int { return m.Status().Routes },
		interfaces:  m.opts.Interfaces,
	}
	if m.opts.Scoped != nil {
		src.scopedRoutes = m.opts.Scoped.Routes
	}
	return src
}

// OutboundRouting reports how Yuhaiin's own outbound sockets are kept out of
// its TUN and which interfaces they leave through. It changes nothing.
func (m *Manager) OutboundRouting(context.Context) sysnet.OutboundRouting {
	m.mu.Lock()
	tunLinks := map[string]int{}
	for _, t := range m.tuns {
		tunLinks[t.Interface] = t.Index
	}
	m.mu.Unlock()
	return buildOutboundRouting(m.outboundSources(), tunLinks)
}

func buildOutboundRouting(src outboundSources, tunLinks map[string]int) sysnet.OutboundRouting {
	p := src.protection()
	own := src.ownTuns()
	isOwn := func(name string) bool { return slices.Contains(own, name) }
	out := sysnet.OutboundRouting{
		Platform: src.goos, State: sysnet.StateActive, Method: p.Method, Mark: p.Mark,
		OwnTuns: append([]string{}, own...), Successes: p.Successes, Failures: p.Failures, LastError: p.LastError,
		ExplicitInterface: src.configured(), Egress: []sysnet.OutboundEgress{}, Interfaces: []sysnet.OutboundInterface{},
	}
	degrade := func(problem string) {
		if out.State == sysnet.StateActive {
			out.State = sysnet.StateDegraded
		}
		out.Problems = append(out.Problems, problem)
	}
	fail := func(problem string) {
		out.State = sysnet.StateFailed
		out.Problems = append(out.Problems, problem)
	}

	markWorks := p.Installed && p.Mark != 0 && p.Failures == 0
	switch src.goos {
	case "linux":
		if out.Method == "" {
			out.Method = "SO_MARK"
			out.Mark = netlink.SocketProtectionMark
		}
		out.ProtectionActive = markWorks
	case "android":
		out.Method = "VpnService.protect"
		out.ProtectionActive = p.Installed && p.Failures == 0
		switch {
		case !p.Installed:
			out.State = sysnet.StateUnavailable
			out.Problems = append(out.Problems, "VpnService.protect is available only while the Yuhaiin VPN runs; until then connections follow the system network")
		case p.Failures > 0:
			degrade(fmt.Sprintf("VpnService.protect failed for %d sockets (last: %s)", p.Failures, p.LastError))
		}
	case "darwin":
		out.Method = "IP_BOUND_IF / IPV6_BOUND_IF"
		out.ProtectionActive = true
	case "windows":
		out.Method = "IP_UNICAST_IF / IPV6_UNICAST_IF"
		out.ProtectionActive = true
	default:
		out.State = sysnet.StateUnsupported
		out.Method = ""
		out.Problems = append(out.Problems, "this platform cannot keep Yuhaiin's own sockets out of a TUN")
	}

	switch {
	case out.ExplicitInterface != "":
		out.EgressMode = sysnet.EgressExplicit
	case len(own) == 0 && src.goos != "android":
		out.EgressMode = sysnet.EgressSystem
	case src.goos == "linux" && markWorks:
		out.EgressMode = sysnet.EgressKernel
	case src.goos == "android" && !p.Installed:
		out.EgressMode = sysnet.EgressSystem
	case src.goos == "android" && p.Failures == 0:
		// Protected sockets leave through the platform's underlying
		// network, chosen by Android for every packet.
		out.EgressMode = sysnet.EgressKernel
	default:
		out.EgressMode = sysnet.EgressBound
	}

	if src.goos == "linux" {
		switch {
		case p.Unavailable != "":
			if len(own) > 0 {
				degrade("SO_MARK is unavailable (" + p.Unavailable + "); outbound sockets are bound to an interface instead, which limits each UDP flow to one network")
			} else {
				out.State = sysnet.StateUnavailable
				out.Problems = append(out.Problems, "SO_MARK is unavailable ("+p.Unavailable+"); needed only while a Yuhaiin TUN is running")
			}
		case p.Failures > 0:
			degrade(fmt.Sprintf("SO_MARK failed for %d sockets (last: %s); those were bound to an interface instead", p.Failures, p.LastError))
		}
		rules, err := src.rules()
		if err != nil {
			degrade("cannot read policy rules: " + err.Error())
		}
		tableInUse := src.tableRoutes() > 0
		for _, r := range rules {
			status := sysnet.OutboundPolicyRule{IPv6: r.IPv6, Priority: r.Priority, Selector: r.Selector, Table: r.Table}
			switch {
			case r.Foreign:
				status.State, status.Error = sysnet.StateConflict, fmt.Sprintf("priority %d is used by another program", r.Priority)
				degrade(status.Error)
			case r.Old:
				status.State, status.Error = sysnet.StateFailed, "an older Yuhaiin rule without the mark exclusion is installed; it is replaced on the next route update"
				fail("the TUN policy rule does not exclude marked sockets; Yuhaiin's own traffic can enter its TUN")
			case r.Present:
				status.State = sysnet.StateActive
			case tableInUse:
				status.State, status.Error = sysnet.StateFailed, "missing while TUN routes are installed"
				degrade("the policy rule for table " + fmt.Sprint(r.Table) + " is missing")
			default:
				status.State = sysnet.StatePending // installed with the first TUN route
			}
			out.Rules = append(out.Rules, status)
		}
		var links []int
		for name, index := range tunLinks {
			if isOwn(name) && index != 0 {
				links = append(links, index)
			}
		}
		if len(links) > 0 {
			if via, err := src.mainViaTun(links); err == nil && len(via) > 0 {
				degrade(fmt.Sprintf("the main table routes %v through a Yuhaiin TUN; protected sockets to those destinations are rejected, not looped", via))
			}
		}
	}

	// Internet egress per family, with our TUN excluded.
	for _, probe := range []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:4860:4860::8888")} {
		e := sysnet.OutboundEgress{IPv6: probe.Is6()}
		switch out.EgressMode {
		case sysnet.EgressExplicit:
			e.Interface = out.ExplicitInterface
		default:
			if c, ok := src.selectRoute(probe, isOwn); ok {
				e.Interface, e.Prefix, e.Metric = c.Interface, c.Prefix.String(), c.Metric
				if c.Gateway.IsValid() {
					e.Gateway = c.Gateway.String()
				}
			} else if src.goos == "android" {
				// Apps cannot read Android's routing table; no entry is
				// not a missing route.
				continue
			} else {
				e.Error = "no route outside Yuhaiin's TUN"
			}
		}
		out.Egress = append(out.Egress, e)
	}
	if len(own) > 0 && out.EgressMode == sysnet.EgressBound && len(out.Egress) == 2 {
		if out.Egress[0].Error != "" && out.Egress[1].Error != "" {
			fail("no interface other than Yuhaiin's TUN routes the Internet; outbound connections fail instead of looping")
		}
	}

	// Interfaces with the default routes and scoped defaults.
	metrics := map[string][2]uint32{}
	for _, d := range src.defaults() {
		m := metrics[d.Interface]
		if d.Prefix.Addr().Is6() {
			m[1] = d.Metric
		} else {
			m[0] = d.Metric
		}
		metrics[d.Interface] = m
	}
	scoped := map[string][2]sysnet.OutboundScopedRoute{}
	if src.scopedRoutes != nil {
		routes, err := src.scopedRoutes()
		if err != nil {
			degrade("interface-scoped routes: " + err.Error())
		}
		for _, r := range routes {
			s := sysnet.OutboundScopedRoute{State: r.State, Link: r.Link, Reason: r.Reason}
			if r.Gateway.IsValid() {
				s.Gateway = r.Gateway.String()
			}
			pair := scoped[r.Interface]
			if r.IPv6 {
				pair[1] = s
			} else {
				pair[0] = s
			}
			scoped[r.Interface] = pair
			if r.State == netlink.ScopedFailed {
				degrade("could not install the scoped default route on " + r.Interface + ": " + r.Reason)
			}
		}
	}
	if list, err := src.interfaces(); err == nil {
		for _, i := range list {
			if i.Type == iface.TypeLoopback {
				continue
			}
			item := sysnet.OutboundInterface{Name: i.Name, Index: i.Index, Type: i.Type, Up: i.Up, Ownership: sysnet.OwnerSystem,
				Addresses: []string{}, Excluded: isOwn(i.Name)}
			switch {
			case item.Excluded:
				item.Ownership = sysnet.OwnerYuhaiin
			case i.Type == iface.TypeTunnel:
				item.Ownership = sysnet.OwnerExternal
			}
			for _, a := range i.Addresses {
				item.Addresses = append(item.Addresses, a.String())
			}
			if i.Gateway.IsValid() {
				item.Gateway = i.Gateway.String()
			}
			if i.GatewayV6.IsValid() {
				item.GatewayV6 = i.GatewayV6.String()
			}
			item.DefaultMetric, item.DefaultMetricV6 = metrics[i.Name][0], metrics[i.Name][1]
			item.Scoped, item.ScopedV6 = scoped[i.Name][0], scoped[i.Name][1]
			out.Interfaces = append(out.Interfaces, item)
		}
	} else {
		degrade("cannot list interfaces: " + err.Error())
	}
	return out
}
