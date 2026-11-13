package sysnet

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
)

// StartMonitor resynchronizes after interface and route changes, so rules
// whose interface disappeared become unavailable and recover when it
// returns. The shared network monitor reports default-route changes; a light
// poll of interface identities, addresses and gateways covers every other
// interface (a VPN appearing, a TUN of another program being recreated).
func (m *Manager) StartMonitor() { m.startMonitor(3 * time.Second) }

func (m *Manager) startMonitor(interval time.Duration) {
	closer := interfaces.AddNetworkMonitor(func(string) { m.Reconcile("network changed") })
	done := make(chan struct{})
	// The baseline is taken now, so a change before the first tick counts.
	last := ""
	if list, err := m.opts.Interfaces(); err == nil {
		last = fingerprint(list)
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			list, err := m.opts.Interfaces()
			if err != nil {
				continue
			}
			if f := fingerprint(list); f != last {
				last = f
				m.Reconcile("interfaces changed")
			}
		}
	}()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopWait = func() { close(done); _ = closer.Close() }
}

func fingerprint(list []iface.Info) string {
	var b strings.Builder
	for _, i := range list {
		fmt.Fprintf(&b, "%d %s %v %s %s %v;", i.Index, i.Name, i.Up, i.Gateway, i.GatewayV6, i.Addresses)
	}
	return b.String()
}

// Interfaces lists current interfaces with ownership, and saved targets
// that are missing.
func (m *Manager) Interfaces(ctx context.Context) (sysnet.Interfaces, error) {
	list, err := m.opts.Interfaces()
	if err != nil {
		return sysnet.Interfaces{}, err
	}
	m.mu.Lock()
	tuns := make(map[string]TunAttachment, len(m.tuns))
	maps.Copy(tuns, m.tuns)
	config := cloneConfig(m.config)
	inbounds := m.inbounds
	m.mu.Unlock()

	byName := map[string]TunAttachment{}
	for _, t := range tuns {
		byName[t.Interface] = t
	}
	caps := m.opts.Capabilities
	out := sysnet.Interfaces{Items: []sysnet.Interface{}, TunInbounds: []sysnet.TunInbound{}}
	for _, i := range list {
		item := sysnet.Interface{Name: i.Name, Index: i.Index, Type: i.Type, Up: i.Up, MTU: i.MTU, HardwareAddr: i.HardwareAddr,
			PointToPoint: i.PointToPoint, Addresses: []string{}, Ownership: sysnet.OwnerSystem}
		for _, a := range i.Addresses {
			item.Addresses = append(item.Addresses, a.String())
		}
		if i.Gateway.IsValid() {
			item.Gateway = i.Gateway.String()
		}
		if i.GatewayV6.IsValid() {
			item.GatewayV6 = i.GatewayV6.String()
		}
		if t, ok := byName[i.Name]; ok {
			item.Ownership, item.InboundID, item.InboundName = sysnet.OwnerYuhaiin, t.InboundID, t.InboundName
		} else if i.Type == iface.TypeTunnel {
			item.Ownership = sysnet.OwnerExternal
		}
		item.Routable = caps.ExternalInterfaces && i.Type != iface.TypeLoopback && item.Ownership != sysnet.OwnerYuhaiin
		out.Items = append(out.Items, item)
	}
	if inbounds != nil {
		out.TunInbounds = inbounds.TunInbounds(ctx)
		out.TProxyInbounds = inbounds.TProxyInbounds(ctx)
	}
	for i := range out.TunInbounds {
		if t, ok := tuns[out.TunInbounds[i].ID]; ok {
			out.TunInbounds[i].Running, out.TunInbounds[i].Interface = true, t.Interface
			out.TunInbounds[i].Platform = t.Platform != nil
		}
	}
	missing := map[string]*sysnet.MissingTarget{}
	var order []string
	note := func(t sysnet.RouteTarget, id string) {
		key := t.Type + "\x00" + t.InboundID + "\x00" + t.InterfaceName
		if missing[key] == nil {
			missing[key] = &sysnet.MissingTarget{Target: t}
			order = append(order, key)
		}
		missing[key].RuleIDs = append(missing[key].RuleIDs, id)
	}
	check := func(t sysnet.RouteTarget, id string) {
		switch t.Type {
		case sysnet.TargetTunInbound:
			if _, ok := tuns[t.InboundID]; !ok {
				note(t, id)
			}
		case sysnet.TargetInterface:
			if _, ok := iface.Find(list, t.InterfaceName, t.HardwareAddr); !ok {
				note(t, id)
			}
		}
	}
	for _, r := range config.Routes {
		check(r.Target, r.ID)
	}
	for _, r := range config.Forwarding.Rules {
		check(r.Egress, r.ID)
		if _, ok := iface.Find(list, r.IngressInterface, ""); !ok {
			note(sysnet.RouteTarget{Type: sysnet.TargetInterface, InterfaceName: r.IngressInterface}, r.ID)
		}
	}
	for _, key := range order {
		out.Missing = append(out.Missing, *missing[key])
	}
	return out, nil
}

// Preview generates a configuration without applying it: route counts per
// rule, overlaps decided by priority, and shadowed rules. Target
// availability is ignored, so the result describes the configuration itself.
func (m *Manager) Preview(_ context.Context, config sysnet.Config) sysnet.Preview {
	out := sysnet.Preview{Rules: []sysnet.RulePreview{}}
	if err := config.Validate(); err != nil {
		out.Error = err.Error()
		return out
	}
	rules := sortedRules(config.Routes)
	var candidates []policy.Candidate
	previews := map[string]*sysnet.RulePreview{}
	for _, r := range rules {
		p := &sysnet.RulePreview{ID: r.ID}
		previews[r.ID] = p
		if !r.Enabled {
			continue
		}
		set, err := policy.Generate(r.Match, m.opts.GeoIP)
		if err != nil {
			p.Error = err.Error()
			continue
		}
		candidates = append(candidates, policy.Candidate{ID: r.ID, Set: set})
	}
	assignments, err := policy.Resolve(candidates)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	for _, a := range assignments {
		p := previews[a.ID]
		routes := policy.Routes(a.Set)
		p.IPv4Routes, p.IPv6Routes = policy.Families(routes)
		p.OverriddenBy, p.Shadowed = a.OverriddenBy, a.Shadowed
		for _, r := range routes[:min(5, len(routes))] {
			p.Sample = append(p.Sample, r.String())
		}
		if len(routes) > policy.MaxRoutesPerRule {
			p.Error = "too many routes for one rule"
		}
		out.Routes += len(routes)
	}
	for _, r := range config.Routes {
		out.Rules = append(out.Rules, *previews[r.ID])
	}
	return out
}

// PlatformRoutes returns the routes rules give a platform TUN that is about to
// start, so its first interface already carries them.
func (m *Manager) PlatformRoutes(inboundID string, ipv4, ipv6 bool) ([]netip.Prefix, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var candidates []policy.Candidate
	var targeted []bool
	for _, r := range sortedRules(m.config.Routes) {
		if !r.Enabled || r.Target.Type != sysnet.TargetTunInbound {
			continue
		}
		set, _, err := m.generate(r)
		if err != nil && set == nil {
			continue
		}
		candidates = append(candidates, policy.Candidate{ID: r.ID, Set: filterFamilies(set, ipv4, ipv6)})
		targeted = append(targeted, r.Target.InboundID == inboundID)
	}
	assignments, err := policy.Resolve(candidates)
	if err != nil {
		return nil, false
	}
	var routes []netip.Prefix
	managed := slices.Contains(targeted, true)
	for i, a := range assignments {
		if targeted[i] {
			routes = append(routes, policy.Routes(a.Set)...)
		}
	}
	return routes, managed
}
