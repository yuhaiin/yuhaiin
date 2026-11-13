//go:build linux && !android

package forward

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// protocol marks rules and routes owned by Yuhaiin (shared with the system
// route manager), so stale ones from a crashed run can be found safely.
const protocol = 0xa5

// Manager applies forwarding plans to the Linux kernel.
type Manager struct {
	Sysctl  *Sysctl
	applied Compiled
	started bool
	// filtered is set while the Yuhaiin nftables table may exist.
	filtered bool
}

func New() *Manager { return &Manager{Sysctl: &Sysctl{}} }

// Supported reports whether this platform has a forwarding applier.
func Supported() bool { return true }

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func familyOf(v6 bool) int {
	if v6 {
		return unix.AF_INET6
	}
	return unix.AF_INET
}

func (r IPRule) netlink() *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = r.Priority
	rule.Table = r.Table
	rule.Family = familyOf(r.V6)
	rule.Protocol = protocol
	rule.IifName = r.Ingress
	if r.Src.IsValid() {
		rule.Src = ipNet(r.Src)
	}
	if r.Mark != 0 {
		rule.Mark = r.Mark
	}
	return rule
}

func (r TableRoute) netlink() *netlink.Route {
	route := &netlink.Route{Table: r.Table, Dst: ipNet(r.Prefix), Protocol: protocol}
	switch {
	case r.Local:
		lo, err := netlink.LinkByName("lo")
		if err == nil {
			route.LinkIndex = lo.Attrs().Index
		}
		route.Type = unix.RTN_LOCAL
		route.Scope = netlink.SCOPE_HOST
	case r.Gateway.IsValid():
		route.LinkIndex = r.Link
		route.Gw = r.Gateway.AsSlice()
	default:
		route.LinkIndex = r.Link
		route.Scope = netlink.SCOPE_LINK
	}
	return route
}

// removeStale deletes rules and routes in the managed ranges carrying the
// Yuhaiin protocol, left by a previous run.
func removeStale() error {
	var result error
	for _, f := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := netlink.RuleList(f)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		for _, r := range rules {
			if r.Protocol == protocol && r.Priority >= TProxyRulePriority && r.Priority <= LastRulePriority {
				if err := netlink.RuleDel(&r); err != nil && !errors.Is(err, unix.ENOENT) {
					result = errors.Join(result, err)
				}
			}
		}
		routes, err := netlink.RouteListFiltered(f, &netlink.Route{Table: unix.RT_TABLE_UNSPEC, Protocol: protocol}, netlink.RT_FILTER_PROTOCOL|netlink.RT_FILTER_TABLE)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		for _, r := range routes {
			if r.Table >= TProxyTable && r.Table <= LastTable {
				if err := netlink.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
					result = errors.Join(result, err)
				}
			}
		}
	}
	return result
}

// Apply makes the kernel match plan. New rules and routes are installed
// before obsolete ones are removed. The nftables table is replaced in one
// transaction, so a rejected firewall update leaves the previous one active.
// On failure, rules and routes added by this call are removed again.
func (m *Manager) Apply(plan Plan) error {
	next, err := Compile(plan)
	if err != nil {
		return err
	}
	if !m.started {
		if len(next.Rules)+len(next.Routes)+len(next.Filter) == 0 && !next.IPv4 && !next.IPv6 {
			// Nothing configured: leave the kernel alone (and work without
			// CAP_NET_ADMIN). Stale state is cleaned once forwarding is used.
			return nil
		}
		if err := removeStale(); err != nil {
			return fmt.Errorf("remove stale forwarding state: %w", err)
		}
		m.started, m.filtered = true, true
	}
	previous := m.applied
	var added []func()
	undo := func(cause error) error {
		for i := len(added) - 1; i >= 0; i-- {
			added[i]()
		}
		return cause
	}
	for _, r := range next.Routes {
		if containsRoute(previous.Routes, r) {
			continue
		}
		route := r.netlink()
		if err := netlink.RouteReplace(route); err != nil {
			return undo(fmt.Errorf("add forwarding route %s table %d: %w", r.Prefix, r.Table, err))
		}
		if !containsTable(previous.Routes, r) {
			added = append(added, func() { _ = netlink.RouteDel(route) })
		}
	}
	for _, r := range next.Rules {
		if containsRule(previous.Rules, r) {
			continue
		}
		rule := r.netlink()
		if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, unix.EEXIST) {
			return undo(fmt.Errorf("add policy rule %s: %w", r, err))
		}
		added = append(added, func() { _ = netlink.RuleDel(rule) })
	}
	if len(next.Filter) != 0 || m.filtered {
		if err := applyFilter(next.Filter); err != nil {
			return undo(fmt.Errorf("apply firewall rules: %w", err))
		}
		m.filtered = len(next.Filter) != 0
	}
	// Enable forwarding only after the rules exist; disable before removal.
	if err := m.Sysctl.Set(SysctlIPv4, next.IPv4); err != nil {
		return undo(err)
	}
	if err := m.Sysctl.Set(SysctlIPv6, next.IPv6); err != nil {
		return undo(err)
	}
	var result error
	for _, r := range previous.Rules {
		if !containsRule(next.Rules, r) {
			if err := netlink.RuleDel(r.netlink()); err != nil && !errors.Is(err, unix.ENOENT) {
				result = errors.Join(result, fmt.Errorf("delete policy rule %s: %w", r, err))
			}
		}
	}
	for _, r := range previous.Routes {
		if !containsRoute(next.Routes, r) && !containsTable(next.Routes, r) {
			if err := netlink.RouteDel(r.netlink()); err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
				result = errors.Join(result, fmt.Errorf("delete forwarding route %s table %d: %w", r.Prefix, r.Table, err))
			}
		}
	}
	m.applied = next
	return result
}

// Close removes every rule, route and the nftables table this manager
// created and restores the sysctls it changed.
func (m *Manager) Close() error {
	if !m.started {
		return nil
	}
	return m.Apply(Plan{})
}

func containsRule(rules []IPRule, r IPRule) bool {
	for _, x := range rules {
		if x == r {
			return true
		}
	}
	return false
}

func containsRoute(routes []TableRoute, r TableRoute) bool {
	for _, x := range routes {
		if x == r {
			return true
		}
	}
	return false
}

// containsTable reports whether another route for the same table and prefix
// exists (it was replaced in place, so it must not be deleted).
func containsTable(routes []TableRoute, r TableRoute) bool {
	for _, x := range routes {
		if x.Table == r.Table && x.Prefix == r.Prefix && x != r {
			return true
		}
	}
	return false
}

func ifname(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name+"\x00")
	return b
}

func matchIface(key expr.MetaKey, name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

// matchPrefix matches the source (or destination) network of the family.
func matchPrefix(p netip.Prefix, source bool) []expr.Any {
	offset, length := uint32(12), uint32(4)
	nfproto := byte(unix.NFPROTO_IPV4)
	if p.Addr().Is6() {
		offset, length, nfproto = 8, 16, unix.NFPROTO_IPV6
	}
	if !source {
		offset += length
	}
	mask := net.CIDRMask(p.Bits(), p.Addr().BitLen())
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: mask, Xor: make([]byte, length)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: p.Masked().Addr().AsSlice()},
	}
}

func filterExprs(r FilterRule) []expr.Any {
	var e []expr.Any
	if r.Ingress != "" {
		e = append(e, matchIface(expr.MetaKeyIIFNAME, r.Ingress)...)
	}
	if r.Egress != "" {
		e = append(e, matchIface(expr.MetaKeyOIFNAME, r.Egress)...)
	}
	if r.Src.IsValid() {
		e = append(e, matchPrefix(r.Src, true)...)
	}
	if r.Dst.IsValid() {
		e = append(e, matchPrefix(r.Dst, false)...)
	}
	switch r.Action {
	case "accept":
		e = append(e, &expr.Verdict{Kind: expr.VerdictAccept})
	case "drop":
		e = append(e, &expr.Verdict{Kind: expr.VerdictDrop})
	case "masquerade":
		e = append(e, &expr.Masq{})
	case "tproxy":
		proto := byte(unix.IPPROTO_TCP)
		if r.Proto == "udp" {
			proto = unix.IPPROTO_UDP
		}
		family := byte(unix.NFPROTO_IPV4)
		if r.Src.Addr().Is6() {
			family = unix.NFPROTO_IPV6
		}
		port := binary.BigEndian.AppendUint16(nil, r.Port)
		e = append(e,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
			&expr.Immediate{Register: 1, Data: binary.NativeEndian.AppendUint32(nil, TProxyMark)},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
			&expr.Immediate{Register: 1, Data: port},
			&expr.TProxy{Family: family, TableFamily: unix.NFPROTO_INET, RegPort: 1},
			&expr.Verdict{Kind: expr.VerdictAccept},
		)
	}
	return e
}

// applyFilter replaces the Yuhaiin nftables table in one batch. Other tables
// are never listed for modification, flushed or deleted.
func applyFilter(rules []FilterRule) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	table := &nftables.Table{Name: NFTTable, Family: nftables.TableFamilyINet}
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return err
	}
	exists := false
	for _, t := range tables {
		if t.Name == NFTTable {
			exists = true
		}
	}
	if exists {
		conn.DelTable(table)
	}
	if len(rules) == 0 {
		if !exists {
			return nil
		}
		return conn.Flush()
	}
	conn.AddTable(table)
	accept := nftables.ChainPolicyAccept
	chains := map[string]*nftables.Chain{
		"forward":     {Name: "forward", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Policy: &accept},
		"postrouting": {Name: "postrouting", Table: table, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource},
		"prerouting":  {Name: "prerouting", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityMangle, Policy: &accept},
	}
	for _, name := range []string{"forward", "postrouting", "prerouting"} {
		conn.AddChain(chains[name])
	}
	for _, r := range rules {
		conn.AddRule(&nftables.Rule{Table: table, Chain: chains[r.Chain], Exprs: filterExprs(r)})
	}
	return conn.Flush()
}
