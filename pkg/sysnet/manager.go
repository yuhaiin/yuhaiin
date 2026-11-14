// Package sysnet is the System Network Manager: the single owner of the
// operating system routes and forwarding state Yuhaiin installs.
//
// TUN inbounds only create and configure their devices and report them with
// AttachTun. Route rules from the saved configuration, the routes a TUN needs
// to work (FakeIP pools) and forwarding rules are resolved here and applied
// through one platform route manager and one forwarding manager. The
// configuration is the desired state; Status reports what was applied.
package sysnet

import (
	"cmp"
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/forward"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"go4.org/netipx"
)

// Store persists the configuration.
type Store interface {
	LoadSystemNetwork(context.Context) (sysnet.Config, error)
	SaveSystemNetwork(context.Context, sysnet.Config) error
}

// RouteApplier is the platform route manager (netlink.RouteManager).
type RouteApplier interface {
	Update([]netlink.SystemRoute) ([]netip.Prefix, error)
	Close() error
}

// ForwardApplier is the platform forwarding manager.
type ForwardApplier interface {
	Apply(forward.Plan) error
	Close() error
}

// Inbounds lists configured inbounds for the editor: TUN inbounds (running or
// not) and TProxy inbounds with their listen address.
type Inbounds interface {
	TunInbounds(context.Context) []sysnet.TunInbound
	TProxyInbounds(context.Context) []sysnet.TProxyInbound
}

// TunAttachment is a running TUN reported by its inbound.
type TunAttachment struct {
	InboundID   string
	InboundName string
	Interface   string
	Index       int
	IPv4, IPv6  bool
	// Required routes keep the TUN working (FakeIP pools, the utun subnet).
	// They take precedence over route rules.
	Required []netip.Prefix
	// Platform receives the routes of a TUN whose routes the platform owns
	// (the Android VpnService) instead of the OS route table. managed is
	// false when no rule targets the TUN.
	Platform func(routes []netip.Prefix, managed bool) error
}

// Options configure a Manager. Nil appliers mark features unsupported.
type Options struct {
	Routes     RouteApplier
	Forward    ForwardApplier
	GeoIP      policy.GeoIPSource
	Interfaces func() ([]iface.Info, error)
	// ListRoutes reads the OS routing table for the system routes view.
	ListRoutes   func() ([]netlink.RouteEntry, []netlink.PolicyRuleEntry, error)
	Capabilities sysnet.Capabilities
}

type ownedRoute struct {
	link   int
	ruleID string
	source string
}

type generated struct {
	key string
	set *netipx.IPSet
}

// Manager reconciles the desired System Network state with the OS.
type Manager struct {
	opts Options

	mu       sync.Mutex
	store    Store
	inbounds Inbounds
	config   sysnet.Config
	loaded   bool
	tuns     map[string]TunAttachment
	// last good generation per rule, kept when regeneration fails.
	cache  map[string]generated
	status sysnet.Status
	closed bool
	// platformApplied remembers what each platform TUN last received.
	platformApplied map[string]string
	// owned records, for the system routes view, which rule each installed
	// route belongs to; platformRoutes what each platform TUN received and
	// platformRule the rule of each of those prefixes;
	// forwardTables which forwarding rule owns each Linux table.
	owned          map[netip.Prefix]ownedRoute
	platformRoutes map[string][]netip.Prefix
	platformRule   map[netip.Prefix]string
	forwardTables  map[int]string

	pending  atomic.Bool
	running  atomic.Bool
	stopWait func()
}

func New(opts Options) *Manager {
	if opts.Interfaces == nil {
		opts.Interfaces = iface.List
	}
	if opts.ListRoutes == nil {
		opts.ListRoutes = netlink.ListRoutes
	}
	m := &Manager{opts: opts, tuns: map[string]TunAttachment{}, cache: map[string]generated{}, platformApplied: map[string]string{},
		owned: map[netip.Prefix]ownedRoute{}, platformRoutes: map[string][]netip.Prefix{}, platformRule: map[netip.Prefix]string{}, forwardTables: map[int]string{}}
	m.status = sysnet.Status{State: sysnet.StatePending, Rules: []sysnet.RuleStatus{}, Capabilities: opts.Capabilities,
		Forwarding: sysnet.ForwardingStatus{State: sysnet.StateDisabled, Rules: []sysnet.ForwardRuleStatus{}}}
	return m
}

// SetStore connects persistence and loads the saved configuration.
func (m *Manager) SetStore(ctx context.Context, store Store) error {
	config, err := store.LoadSystemNetwork(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store, m.config, m.loaded = store, config, true
	m.reconcileLocked("configuration loaded")
	return nil
}

// SetInbounds connects the inbound catalog used by the editor.
func (m *Manager) SetInbounds(inbounds Inbounds) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inbounds = inbounds
}

func (m *Manager) Capabilities() sysnet.Capabilities { return m.opts.Capabilities }

// Config returns the saved configuration.
func (m *Manager) Config(context.Context) (sysnet.Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.loaded {
		return sysnet.Config{}, errors.New("the System Network configuration is not loaded")
	}
	return cloneConfig(m.config), nil
}

func cloneConfig(c sysnet.Config) sysnet.Config {
	data, _ := json.Marshal(c)
	var out sysnet.Config
	_ = json.Unmarshal(data, &out)
	if out.Routes == nil {
		out.Routes = []sysnet.RouteRule{}
	}
	if out.Forwarding.Rules == nil {
		out.Forwarding.Rules = []sysnet.ForwardRule{}
	}
	return out
}

// Save validates and persists config, then applies it. Migration records are
// owned by the core and kept as they are. An apply failure is reported in the
// returned status, not as an error: the configuration is saved either way.
func (m *Manager) Save(ctx context.Context, config sysnet.Config) (sysnet.SaveResult, error) {
	if err := config.Validate(); err != nil {
		return sysnet.SaveResult{}, err
	}
	if err := m.checkSupported(config); err != nil {
		return sysnet.SaveResult{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store == nil {
		return sysnet.SaveResult{}, errors.New("the System Network configuration storage is unavailable")
	}
	config.Migrations = m.config.Migrations
	if err := m.store.SaveSystemNetwork(ctx, config); err != nil {
		return sysnet.SaveResult{}, err
	}
	m.config, m.loaded = config, true
	m.reconcileLocked("configuration saved")
	return sysnet.SaveResult{Config: cloneConfig(m.config), Status: m.statusLocked()}, nil
}

// checkSupported rejects configuration the platform cannot represent, so an
// unsupported feature is never saved as if it worked.
func (m *Manager) checkSupported(config sysnet.Config) error {
	caps := m.opts.Capabilities
	for _, r := range config.Routes {
		if !slices.Contains(caps.RouteTargets, r.Target.Type) {
			return fmt.Errorf("route rule %q: target %q is not supported on %s", r.Name, r.Target.Type, caps.Platform)
		}
	}
	if (config.Forwarding.IPv4 && !caps.IPv4Forwarding) || (config.Forwarding.IPv6 && !caps.IPv6Forwarding) {
		return fmt.Errorf("forwarding is not supported on %s", caps.Platform)
	}
	for _, r := range config.Forwarding.Rules {
		if !slices.Contains(caps.ForwardTargets, r.Egress.Type) {
			return fmt.Errorf("forwarding rule %q: egress %q is not supported on %s", r.Name, r.Egress.Type, caps.Platform)
		}
		if r.Masquerade && !caps.NAT {
			return fmt.Errorf("forwarding rule %q: NAT is not supported on %s", r.Name, caps.Platform)
		}
		if len(r.SourceCIDRs) != 0 && !caps.ForwardSourceFilter {
			return fmt.Errorf("forwarding rule %q: %s forwards every device on the ingress; remove the source CIDRs", r.Name, caps.Platform)
		}
	}
	return nil
}

// AttachTun registers or updates a running TUN and resynchronizes routes.
func (m *Manager) AttachTun(a TunAttachment) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tuns[a.InboundID] = a
	m.reconcileLocked("TUN " + a.InboundID + " attached")
}

// DetachTun removes a TUN's routes before its device is closed.
func (m *Manager) DetachTun(inboundID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tuns[inboundID]; !ok {
		return
	}
	delete(m.tuns, inboundID)
	delete(m.platformApplied, inboundID)
	delete(m.platformRoutes, inboundID)
	m.reconcileLocked("TUN " + inboundID + " detached")
}

// Reconcile schedules a resynchronization (network change, GeoIP update).
// Bursts are coalesced into one run at a time.
func (m *Manager) Reconcile(reason string) {
	m.pending.Store(true)
	if !m.running.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer m.running.Store(false)
		for m.pending.Swap(false) {
			m.mu.Lock()
			if !m.closed {
				m.reconcileLocked(reason)
			}
			m.mu.Unlock()
		}
	}()
}

// Status returns the runtime state.
func (m *Manager) Status() sysnet.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

func (m *Manager) statusLocked() sysnet.Status {
	s := m.status
	s.Rules = slices.Clone(s.Rules)
	s.Required = slices.Clone(s.Required)
	s.Forwarding.Rules = slices.Clone(s.Forwarding.Rules)
	s.Migrations = slices.Clone(m.config.Migrations)
	s.Capabilities = m.opts.Capabilities
	return s
}

// Close removes every route and forwarding change this manager made.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	if m.stopWait != nil {
		m.stopWait()
	}
	var err error
	if m.opts.Forward != nil {
		err = errors.Join(err, m.opts.Forward.Close())
	}
	if m.opts.Routes != nil {
		err = errors.Join(err, m.opts.Routes.Close())
	}
	return err
}

// target is a resolved rule target.
type target struct {
	name               string
	link               int
	gateway, gateway6  netip.Addr
	ipv4, ipv6         bool
	platform           func([]netip.Prefix, bool) error
	platformID         string
	state, err, detail string
}

func (m *Manager) resolveTarget(t sysnet.RouteTarget, ifaces []iface.Info) target {
	switch t.Type {
	case sysnet.TargetTunInbound:
		tun, ok := m.tuns[t.InboundID]
		if !ok {
			return target{state: sysnet.StateUnavailable, err: "the TUN inbound is not running"}
		}
		return target{name: tun.Interface, link: tun.Index, ipv4: tun.IPv4, ipv6: tun.IPv6, platform: tun.Platform, platformID: tun.InboundID}
	case sysnet.TargetInterface:
		info, ok := iface.Find(ifaces, t.InterfaceName, t.HardwareAddr)
		if !ok {
			return target{state: sysnet.StateUnavailable, err: fmt.Sprintf("interface %s does not exist", t.InterfaceName)}
		}
		if !info.Up {
			return target{name: info.Name, state: sysnet.StateUnavailable, err: fmt.Sprintf("interface %s is down", info.Name)}
		}
		r := target{name: info.Name, link: info.Index}
		if !info.NeedsGateway() {
			r.ipv4, r.ipv6 = info.HasFamily(false), info.HasFamily(true)
			return r
		}
		var problems []string
		gw := func(explicit string, detected netip.Addr, v6 bool) (netip.Addr, bool) {
			family := "IPv4"
			if v6 {
				family = "IPv6"
			}
			if explicit != "" {
				a := netip.MustParseAddr(explicit)
				if !info.OnLink(a) {
					problems = append(problems, fmt.Sprintf("%s gateway %s is not on the network of %s", family, a, info.Name))
					return netip.Addr{}, false
				}
				return a, true
			}
			if detected.IsValid() {
				return detected, true
			}
			if info.HasFamily(v6) {
				problems = append(problems, fmt.Sprintf("no %s gateway found on %s; set one in the rule's advanced settings", family, info.Name))
			}
			return netip.Addr{}, false
		}
		r.gateway, r.ipv4 = gw(t.Gateway, info.Gateway, false)
		r.gateway6, r.ipv6 = gw(t.GatewayV6, info.GatewayV6, true)
		if len(problems) != 0 {
			r.detail = joinProblems(problems)
			if !r.ipv4 && !r.ipv6 {
				r.state, r.err = sysnet.StateFailed, r.detail
			}
		}
		return r
	}
	return target{state: sysnet.StateUnsupported, err: fmt.Sprintf("target %q is not a route target", t.Type)}
}

func joinProblems(p []string) string {
	var out strings.Builder
	for i, s := range p {
		if i > 0 {
			out.WriteString("; ")
		}
		out.WriteString(s)
	}
	return out.String()
}

// sortedRules returns enabled and disabled rules in evaluation order.
func sortedRules(rules []sysnet.RouteRule) []sysnet.RouteRule {
	out := slices.Clone(rules)
	slices.SortStableFunc(out, func(a, b sysnet.RouteRule) int { return cmp.Compare(a.Priority, b.Priority) })
	return out
}

func matchKey(m sysnet.RouteMatch) string {
	data, _ := json.Marshal(m)
	return string(data)
}

// generate returns a rule's destinations, keeping the previous result when
// regeneration fails (for example while the GeoIP database is not loaded) so
// working routes are never emptied by a transient error.
func (m *Manager) generate(rule sysnet.RouteRule) (*netipx.IPSet, bool, error) {
	key := matchKey(rule.Match)
	set, err := policy.Generate(rule.Match, m.opts.GeoIP)
	if err == nil {
		m.cache[rule.ID] = generated{key: key, set: set}
		return set, false, nil
	}
	if previous, ok := m.cache[rule.ID]; ok && previous.key == key {
		return previous.set, true, err
	}
	return nil, false, err
}

func filterFamilies(set *netipx.IPSet, v4, v6 bool) *netipx.IPSet {
	var b netipx.IPSetBuilder
	b.AddSet(set)
	if !v4 {
		b.RemovePrefix(netip.MustParsePrefix("0.0.0.0/0"))
	}
	if !v6 {
		b.RemovePrefix(netip.MustParsePrefix("::/0"))
	}
	out, _ := b.IPSet()
	return out
}

type candidateInfo struct {
	rule     *sysnet.RouteRule
	required *TunAttachment
	target   target
	status   *sysnet.RuleStatus
}

// reconcileLocked computes and applies the desired state. m.mu is held.
func (m *Manager) reconcileLocked(reason string) {
	if m.closed {
		return
	}
	caps := m.opts.Capabilities
	ifaces, ifaceErr := m.opts.Interfaces()
	status := sysnet.Status{State: sysnet.StateActive, Generation: m.status.Generation + 1, Rules: []sysnet.RuleStatus{},
		Forwarding: sysnet.ForwardingStatus{State: sysnet.StateDisabled, Rules: []sysnet.ForwardRuleStatus{}}}
	if ifaceErr != nil && m.needsInterfaces() {
		// Only rules that name interfaces depend on the list; TUN targets and
		// the Android VPN do not.
		status.State, status.Error = sysnet.StateDegraded, "list interfaces: "+ifaceErr.Error()
	}

	var candidates []policy.Candidate
	var infos []candidateInfo
	// Required TUN routes first, in a stable order.
	tunIDs := make([]string, 0, len(m.tuns))
	for id := range m.tuns {
		tunIDs = append(tunIDs, id)
	}
	slices.Sort(tunIDs)
	for _, id := range tunIDs {
		tun := m.tuns[id]
		if len(tun.Required) == 0 || tun.Platform != nil {
			continue
		}
		set := filterFamilies(policy.SetOf(tun.Required), tun.IPv4, tun.IPv6)
		candidates = append(candidates, policy.Candidate{ID: "required:" + id, Set: set})
		infos = append(infos, candidateInfo{required: &tun, target: target{name: tun.Interface, link: tun.Index, ipv4: tun.IPv4, ipv6: tun.IPv6}})
	}
	rules := sortedRules(m.config.Routes)
	statusByID := map[string]*sysnet.RuleStatus{}
	for i := range rules {
		rule := &rules[i]
		rs := &sysnet.RuleStatus{ID: rule.ID, State: sysnet.StatePending}
		statusByID[rule.ID] = rs
		if !rule.Enabled {
			rs.State = sysnet.StateDisabled
			continue
		}
		if !caps.RouteManagement || !slices.Contains(caps.RouteTargets, rule.Target.Type) {
			rs.State, rs.Error = sysnet.StateUnsupported, "this platform cannot apply this rule"
			continue
		}
		t := m.resolveTarget(rule.Target, ifaces)
		rs.Interface, rs.InterfaceIndex = t.name, t.link
		if t.state != "" {
			rs.State, rs.Error = t.state, t.err
			continue
		}
		set, stale, err := m.generate(*rule)
		if err != nil {
			rs.Error = err.Error()
			if !stale {
				rs.State = sysnet.StateFailed
				continue
			}
			rs.Stale = true
		}
		if t.detail != "" {
			rs.Error = joinProblems(append(nonEmpty(rs.Error), t.detail))
		}
		set = filterFamilies(set, t.ipv4, t.ipv6)
		candidates = append(candidates, policy.Candidate{ID: rule.ID, Set: set})
		infos = append(infos, candidateInfo{rule: rule, target: t, status: rs})
	}
	assignments, err := policy.Resolve(candidates)
	if err != nil {
		status.State, status.Error = sysnet.StateFailed, err.Error()
		m.finish(status, rules, statusByID)
		return
	}

	var desired []netlink.SystemRoute
	owner := map[netip.Prefix]int{}
	owned := map[netip.Prefix]ownedRoute{}
	platform := map[string][]netip.Prefix{}
	platformManaged := map[string]bool{}
	platformRule := map[netip.Prefix]string{}
	for i, a := range assignments {
		info := infos[i]
		routes := policy.Routes(a.Set)
		if info.status != nil {
			info.status.OverriddenBy = removeRequired(a.OverriddenBy)
			info.status.Shadowed = a.Shadowed
			info.status.IPv4Routes, info.status.IPv6Routes = policy.Families(routes)
			if len(routes) > policy.MaxRoutesPerRule {
				info.status.State, info.status.Error = sysnet.StateFailed, fmt.Sprintf("rule generates %d routes, more than the limit of %d", len(routes), policy.MaxRoutesPerRule)
				info.status.IPv4Routes, info.status.IPv6Routes = 0, 0
				continue
			}
		}
		if info.target.platform != nil {
			platform[info.target.platformID] = append(platform[info.target.platformID], routes...)
			platformManaged[info.target.platformID] = true
			for _, p := range routes {
				platformRule[p] = a.ID
			}
			continue
		}
		source, ruleID := sysnet.SourceRule, a.ID
		if info.required != nil {
			source, ruleID = sysnet.SourceRequired, info.required.InboundID
		}
		for _, p := range routes {
			owned[p] = ownedRoute{link: info.target.link, ruleID: ruleID, source: source}
			r := netlink.SystemRoute{Prefix: p, Link: info.target.link}
			if p.Addr().Is4() {
				r.Gateway = info.target.gateway
			} else {
				r.Gateway = info.target.gateway6
			}
			owner[p] = i
			desired = append(desired, r)
		}
	}
	if len(desired) > policy.MaxRoutes {
		status.State, status.Error = sysnet.StateFailed, fmt.Sprintf("%d routes exceed the limit of %d; previous routes are kept", len(desired), policy.MaxRoutes)
		m.finishKeep(status, rules, statusByID)
		return
	}

	var applyErr error
	if m.opts.Routes != nil {
		conflicts, err := m.opts.Routes.Update(desired)
		applyErr = err
		for _, p := range conflicts {
			info := infos[owner[p]]
			if info.status != nil {
				info.status.Conflicts = append(info.status.Conflicts, p.String())
			} else if info.required != nil {
				status.Required = appendRequiredConflict(status.Required, *info.required, p)
			}
		}
	} else if len(desired) != 0 {
		applyErr = netlink.ErrRoutesUnsupported
	}
	for _, id := range tunIDs {
		tun := m.tuns[id]
		if tun.Platform == nil {
			if len(tun.Required) != 0 {
				status.Required = ensureRequired(status.Required, tun)
			}
			continue
		}
		routes := platform[id]
		fingerprint := fmt.Sprint(platformManaged[id], routes)
		if m.platformApplied[id] == fingerprint {
			continue
		}
		if err := tun.Platform(routes, platformManaged[id]); err != nil {
			applyErr = errors.Join(applyErr, fmt.Errorf("apply routes to %s: %w", tun.InboundName, err))
			continue
		}
		m.platformApplied[id] = fingerprint
		m.platformRoutes[id] = slices.Clone(routes)
	}
	// A fresh map each reconcile, so SystemRoutes may read it unlocked.
	m.platformRule = platformRule
	for _, info := range infos {
		if info.status == nil || info.status.State != sysnet.StatePending {
			continue
		}
		switch {
		case applyErr != nil:
			info.status.State = sysnet.StateFailed
			info.status.Error = joinProblems(append(nonEmpty(info.status.Error), applyErr.Error()))
		case len(info.status.Conflicts) != 0:
			info.status.State = sysnet.StateConflict
		case info.status.Stale || info.target.detail != "":
			info.status.State = sysnet.StateDegraded
		default:
			info.status.State = sysnet.StateActive
		}
	}
	if applyErr == nil {
		m.owned = owned
	}
	if applyErr != nil {
		status.State, status.Error = sysnet.StateFailed, applyErr.Error()
		log.Error("apply system routes failed; previous routes are kept", "reason", reason, "err", applyErr)
	}
	status.Routes = len(desired)
	for _, n := range platform {
		status.Routes += len(n)
	}
	current := make([]sysnet.RuleStatus, 0, len(statusByID))
	for _, rs := range statusByID {
		if rs.State == sysnet.StateActive || rs.State == sysnet.StateDegraded || rs.State == sysnet.StateConflict {
			current = append(current, *rs)
		}
	}
	status.Forwarding = m.applyForwarding(ifaces, current)
	if status.State == sysnet.StateActive && status.Forwarding.State == sysnet.StateFailed {
		status.State, status.Error = sysnet.StateDegraded, status.Forwarding.Error
	}
	m.finish(status, rules, statusByID)
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func removeRequired(ids []string) []string {
	var out []string
	for _, id := range ids {
		if len(id) < 9 || id[:9] != "required:" {
			out = append(out, id)
		}
	}
	return out
}

func ensureRequired(list []sysnet.RequiredRoutes, tun TunAttachment) []sysnet.RequiredRoutes {
	for _, r := range list {
		if r.InboundID == tun.InboundID {
			return list
		}
	}
	prefixes := make([]string, 0, len(tun.Required))
	for _, p := range tun.Required {
		prefixes = append(prefixes, p.String())
	}
	return append(list, sysnet.RequiredRoutes{InboundID: tun.InboundID, Interface: tun.Interface, Prefixes: prefixes})
}

func appendRequiredConflict(list []sysnet.RequiredRoutes, tun TunAttachment, p netip.Prefix) []sysnet.RequiredRoutes {
	list = ensureRequired(list, tun)
	for i := range list {
		if list[i].InboundID == tun.InboundID {
			list[i].Conflicts = append(list[i].Conflicts, p.String())
		}
	}
	return list
}

// finishKeep records a failed generation without touching applied routes.
func (m *Manager) finishKeep(status sysnet.Status, rules []sysnet.RouteRule, byID map[string]*sysnet.RuleStatus) {
	for _, rs := range byID {
		if rs.State == sysnet.StatePending {
			rs.State, rs.Error = sysnet.StateFailed, status.Error
		}
	}
	status.Forwarding = m.status.Forwarding
	m.finish(status, rules, byID)
}

func (m *Manager) finish(status sysnet.Status, rules []sysnet.RouteRule, byID map[string]*sysnet.RuleStatus) {
	// Report rules in configuration order.
	for _, r := range m.config.Routes {
		if rs, ok := byID[r.ID]; ok {
			status.Rules = append(status.Rules, *rs)
		}
	}
	_ = rules
	status.AppliedAt = time.Now().Unix()
	m.status = status
}

// applyForwarding resolves and applies the forwarding configuration.
func (m *Manager) applyForwarding(ifaces []iface.Info, routeRules []sysnet.RuleStatus) sysnet.ForwardingStatus {
	cfg := m.config.Forwarding
	fs := sysnet.ForwardingStatus{State: sysnet.StateDisabled, Rules: []sysnet.ForwardRuleStatus{}}
	if m.opts.Forward == nil {
		if cfg.IPv4 || cfg.IPv6 {
			fs.State, fs.Error = sysnet.StateUnsupported, forward.ErrUnsupported.Error()
		}
		return fs
	}
	plan := forward.Plan{IPv4: cfg.IPv4, IPv6: cfg.IPv6}
	var tproxy []sysnet.TProxyInbound
	if m.inbounds != nil {
		tproxy = m.inbounds.TProxyInbounds(context.Background())
	}
	for _, rule := range cfg.Rules {
		rs := sysnet.ForwardRuleStatus{ID: rule.ID, State: sysnet.StatePending, Ingress: rule.IngressInterface, Masquerade: rule.Masquerade}
		if !rule.Enabled {
			rs.State = sysnet.StateDisabled
			fs.Rules = append(fs.Rules, rs)
			continue
		}
		in, ok := iface.Find(ifaces, rule.IngressInterface, "")
		if !ok {
			rs.State, rs.Error = sysnet.StateUnavailable, fmt.Sprintf("ingress interface %s does not exist", rule.IngressInterface)
			fs.Rules = append(fs.Rules, rs)
			continue
		}
		sources, _ := sysnet.ParseCIDRs("source", rule.SourceCIDRs)
		destinations, _ := sysnet.ParseCIDRs("destination", rule.DestinationCIDRs)
		planned := forward.Rule{ID: rule.ID, Ingress: in.Name, IngressLink: in.Index, Sources: sources, Destinations: destinations, Masquerade: rule.Masquerade}
		if rule.Egress.Type == sysnet.TargetRoutes {
			planned.Egress = forward.Egress{Routes: true}
			rs.Egress = "routes"
		} else if rule.Egress.Type == sysnet.TargetTProxy {
			port := tproxyPort(tproxy, rule.Egress.InboundID)
			if port == 0 {
				rs.State, rs.Error = sysnet.StateUnavailable, "the TProxy inbound does not exist or has no listen port"
				fs.Rules = append(fs.Rules, rs)
				continue
			}
			planned.Egress = forward.Egress{Name: "tproxy", TProxyPort: port}
			rs.Egress = "TProxy :" + fmt.Sprint(port)
		} else {
			t := m.resolveTarget(rule.Egress, ifaces)
			if t.state != "" {
				rs.State, rs.Error = t.state, t.err
				fs.Rules = append(fs.Rules, rs)
				continue
			}
			if t.platform != nil {
				rs.State, rs.Error = sysnet.StateUnsupported, "this TUN's routes are managed by the platform"
				fs.Rules = append(fs.Rules, rs)
				continue
			}
			planned.Egress = forward.Egress{Name: t.name, Link: t.link, Gateway: t.gateway, GatewayV6: t.gateway6}
			rs.Egress = t.name
			if t.detail != "" {
				rs.Error = t.detail
			}
		}
		plan.Rules = append(plan.Rules, planned)
		fs.Rules = append(fs.Rules, rs)
	}
	plan.Links = forwardLinks(ifaces, routeRules, m.tuns)
	m.forwardTables = map[int]string{}
	for i, r := range plan.Rules {
		m.forwardTables[forward.FirstTable+i] = r.ID
	}
	err := m.opts.Forward.Apply(plan)
	fs.IPv4, fs.IPv6 = cfg.IPv4, cfg.IPv6
	switch {
	case err != nil:
		fs.State, fs.Error = sysnet.StateFailed, err.Error()
	case cfg.IPv4 || cfg.IPv6:
		fs.State = sysnet.StateActive
	}
	for i := range fs.Rules {
		if fs.Rules[i].State != sysnet.StatePending {
			continue
		}
		switch {
		case err != nil:
			fs.Rules[i].State, fs.Rules[i].Error = sysnet.StateFailed, err.Error()
		case !cfg.IPv4 && !cfg.IPv6:
			fs.Rules[i].State = sysnet.StateDisabled
		case fs.Rules[i].Error != "":
			fs.Rules[i].State = sysnet.StateDegraded
		default:
			fs.Rules[i].State = sysnet.StateActive
		}
	}
	return fs
}

func tproxyPort(list []sysnet.TProxyInbound, id string) uint16 {
	for _, t := range list {
		if t.ID != id {
			continue
		}
		if ap, err := netip.ParseAddrPort(t.Listen); err == nil {
			return ap.Port()
		}
		var port uint16
		if _, err := fmt.Sscanf(t.Listen[lastColon(t.Listen)+1:], "%d", &port); err == nil {
			return port
		}
	}
	return 0
}

func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

// forwardLinks returns interfaces forwarded traffic may leave through when it
// follows the routing table: interfaces with a default gateway, targets of
// active route rules and attached TUNs.
func forwardLinks(ifaces []iface.Info, rules []sysnet.RuleStatus, tuns map[string]TunAttachment) []int {
	seen := map[int]bool{}
	var out []int
	add := func(link int) {
		if link > 0 && !seen[link] {
			seen[link] = true
			out = append(out, link)
		}
	}
	for _, i := range ifaces {
		if i.Up && (i.Gateway.IsValid() || i.GatewayV6.IsValid()) {
			add(i.Index)
		}
	}
	for _, r := range rules {
		add(r.InterfaceIndex)
	}
	for _, t := range tuns {
		if t.Platform == nil {
			add(t.Index)
		}
	}
	slices.Sort(out)
	return out
}

// needsInterfaces reports whether enabled rules refer to interfaces by name.
func (m *Manager) needsInterfaces() bool {
	for _, r := range m.config.Routes {
		if r.Enabled && r.Target.Type == sysnet.TargetInterface {
			return true
		}
	}
	for _, r := range m.config.Forwarding.Rules {
		if r.Enabled {
			return true
		}
	}
	return false
}
