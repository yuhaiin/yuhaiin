// Package forward manages forwarding of other devices' traffic (side router).
//
//   - Linux: kernel IP forwarding, per-rule policy routing towards an egress,
//     a Yuhaiin-only nftables table with masquerade and TProxy interception.
//   - macOS: IP forwarding sysctls and a PF anchor (com.apple/yuhaiin) with
//     route-to, source restriction and NAT.
//   - Windows: per-interface forwarding; forwarded traffic follows the
//     routing table (including System Network route rules).
//
// The plan compilers and the ownership of changed settings are platform
// independent and unit tested; the appliers only talk to the kernel.
package forward

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// ErrUnsupported is returned where forwarding cannot be applied.
var ErrUnsupported = errors.New("forwarding is only supported on Linux")

// Managed ranges. Forwarding rules sit before the System Network route rule
// (30001/30002) so traffic of a forwarding rule leaves through its egress
// even when a route rule also matches the destination.
const (
	TProxyRulePriority = 28999
	FirstRulePriority  = 29000
	LastRulePriority   = 29999
	TProxyTable        = 6299
	FirstTable         = 6300
	LastTable          = 6555
	// TProxyMark marks intercepted packets for the local delivery table.
	TProxyMark = 0x5953
	// NFTTable is the only nftables table this package creates or deletes.
	NFTTable = "yuhaiin_sysnet"
)

// Plan is the resolved desired forwarding state. Links are further
// interfaces traffic may leave through when it follows the routing table
// (route rule targets and interfaces with a default gateway); per-interface
// forwarding (Windows) is enabled on them.
type Plan struct {
	IPv4, IPv6 bool
	Rules      []Rule
	Links      []int
}

// sources returns a rule's sources of one family; no sources means all.
func (r Rule) sources(v6 bool) []netip.Prefix {
	if len(r.Sources) == 0 {
		if v6 {
			return []netip.Prefix{netip.MustParsePrefix("::/0")}
		}
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	}
	return split(r.Sources, v6)
}

// Rule is a forwarding rule with interfaces already resolved. Empty Sources
// mean every device on the ingress.
type Rule struct {
	ID           string
	Ingress      string
	IngressLink  int
	Sources      []netip.Prefix
	Destinations []netip.Prefix
	Egress       Egress
	Masquerade   bool
}

// Egress is where a rule's traffic leaves: a route through an interface,
// the system routing table (Routes), or TProxy interception into a local
// transparent listener.
type Egress struct {
	Name      string
	Link      int
	Gateway   netip.Addr
	GatewayV6 netip.Addr
	// Routes forwards through the system routing table, which already holds
	// the System Network route rules.
	Routes bool
	// TProxyPort is set for TProxy interception instead of a route.
	TProxyPort uint16
}

func (e Egress) tproxy() bool { return e.TProxyPort != 0 }

// IPRule is a policy routing rule. Src is empty for the TProxy mark rule.
type IPRule struct {
	Priority int
	Table    int
	V6       bool
	Ingress  string
	Src      netip.Prefix
	Mark     uint32
}

func (r IPRule) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "prio %d", r.Priority)
	if r.Ingress != "" {
		fmt.Fprintf(&b, " iif %s", r.Ingress)
	}
	if r.Src.IsValid() {
		fmt.Fprintf(&b, " from %s", r.Src)
	}
	if r.Mark != 0 {
		fmt.Fprintf(&b, " fwmark %#x", r.Mark)
	}
	fmt.Fprintf(&b, " lookup %d", r.Table)
	if r.V6 {
		b.WriteString(" (ipv6)")
	}
	return b.String()
}

// TableRoute is a route in a forwarding table. Local routes deliver TProxy
// traffic to this host.
type TableRoute struct {
	Table   int
	Prefix  netip.Prefix
	Link    int
	Gateway netip.Addr
	Local   bool
}

// FilterRule is one nftables rule in the Yuhaiin table.
type FilterRule struct {
	Chain   string // "forward", "postrouting" or "prerouting"
	Ingress string
	Egress  string
	Src     netip.Prefix
	Dst     netip.Prefix
	// Action is "accept", "drop", "masquerade" or "tproxy".
	Action string
	Proto  string // "tcp" or "udp" for tproxy
	Port   uint16
}

// Compiled is the kernel state that realizes a Plan.
type Compiled struct {
	IPv4, IPv6 bool
	Rules      []IPRule
	Routes     []TableRoute
	Filter     []FilterRule
}

func split(p []netip.Prefix, v6 bool) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range p {
		if x.Addr().Is6() == v6 {
			out = append(out, x)
		}
	}
	return out
}

func defaults(v6 bool) []netip.Prefix {
	if v6 {
		return []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
	}
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
}

// Compile turns a plan into policy rules, table routes and filter rules.
//
//   - Each route rule gets its own table holding its destinations (or the
//     whole internet as two /1 routes) through the egress, and one policy
//     rule per source CIDR selecting that table for traffic from the ingress.
//     Destinations outside the table fall through to the next rules.
//   - The forward chain accepts configured sources from each ingress and
//     drops other forwarded traffic from that ingress, so only the selected
//     devices are forwarded. Other interfaces are not affected.
//   - Masquerade rewrites sources leaving the egress, only when enabled.
//   - TProxy rules mark matching TCP and UDP from the ingress and hand it to
//     the local transparent listener through a local-delivery table.
//
// A family is skipped unless its kernel forwarding is enabled.
func Compile(plan Plan) (Compiled, error) {
	c := Compiled{IPv4: plan.IPv4, IPv6: plan.IPv6}
	if len(plan.Rules) > LastTable-FirstTable+1 {
		return Compiled{}, fmt.Errorf("too many forwarding rules")
	}
	ingresses := []string{}
	// tproxy records, per family, the ingresses whose traffic is intercepted.
	tproxy := map[bool][]string{}
	for i, rule := range plan.Rules {
		priority := FirstRulePriority + i
		table := FirstTable + i
		if !slices.Contains(ingresses, rule.Ingress) {
			ingresses = append(ingresses, rule.Ingress)
		}
		for _, v6 := range []bool{false, true} {
			if (v6 && !plan.IPv6) || (!v6 && !plan.IPv4) {
				continue
			}
			sources := rule.sources(v6)
			if len(sources) == 0 {
				continue
			}
			destinations := split(rule.Destinations, v6)
			for _, src := range sources {
				c.Filter = append(c.Filter, FilterRule{Chain: "forward", Ingress: rule.Ingress, Src: src, Action: "accept"})
			}
			if rule.Egress.Routes {
				// The forward chain accepts it; the main table and route rules route it.
				continue
			}
			if rule.Egress.tproxy() {
				if !slices.Contains(tproxy[v6], rule.Ingress) {
					tproxy[v6] = append(tproxy[v6], rule.Ingress)
				}
				dsts := destinations
				if len(dsts) == 0 {
					dsts = []netip.Prefix{{}}
				}
				for _, src := range sources {
					for _, dst := range dsts {
						for _, proto := range []string{"tcp", "udp"} {
							c.Filter = append(c.Filter, FilterRule{Chain: "prerouting", Ingress: rule.Ingress, Src: src, Dst: dst, Action: "tproxy", Proto: proto, Port: rule.Egress.TProxyPort})
						}
					}
				}
				continue
			}
			gw := rule.Egress.Gateway
			if v6 {
				gw = rule.Egress.GatewayV6
			}
			routes := destinations
			if len(routes) == 0 {
				routes = defaults(v6)
			}
			for _, dst := range routes {
				c.Routes = append(c.Routes, TableRoute{Table: table, Prefix: dst, Link: rule.Egress.Link, Gateway: gw})
			}
			for _, src := range sources {
				c.Rules = append(c.Rules, IPRule{Priority: priority, Table: table, V6: v6, Ingress: rule.Ingress, Src: src})
				if rule.Masquerade {
					c.Filter = append(c.Filter, FilterRule{Chain: "postrouting", Egress: rule.Egress.Name, Src: src, Action: "masquerade"})
				}
			}
		}
	}
	for _, v6 := range []bool{false, true} {
		if len(tproxy[v6]) == 0 {
			continue
		}
		local := netip.MustParsePrefix("0.0.0.0/0")
		if v6 {
			local = netip.MustParsePrefix("::/0")
		}
		// The mark rule is limited to the ingress: reverse-path checks look
		// up the source from "lo", and with src_valid_mark a rule for every
		// interface would make the client's address look local and drop it.
		for _, ingress := range tproxy[v6] {
			c.Rules = append(c.Rules, IPRule{Priority: TProxyRulePriority, Table: TProxyTable, V6: v6, Ingress: ingress, Mark: TProxyMark})
		}
		c.Routes = append(c.Routes, TableRoute{Table: TProxyTable, Prefix: local, Local: true})
	}
	for _, ingress := range ingresses {
		c.Filter = append(c.Filter, FilterRule{Chain: "forward", Ingress: ingress, Action: "drop"})
	}
	if !plan.IPv4 && !plan.IPv6 {
		c.Filter = nil
	}
	return c, nil
}

// Sysctl owns kernel settings this package changes. It records the value
// before the first change and restores it only if the setting still has the
// value written here, so a setting another service changed meanwhile, or
// one that was already enabled, is never reverted.
type Sysctl struct {
	Root string // "/proc/sys" by default
	// ReadValue and WriteValue replace /proc/sys access (macOS sysctl).
	ReadValue  func(key string) (string, error)
	WriteValue func(key, value string) error
	mu         sync.Mutex
	previous   map[string]string
}

func (s *Sysctl) path(key string) string {
	root := s.Root
	if root == "" {
		root = "/proc/sys"
	}
	return filepath.Join(root, filepath.FromSlash(strings.ReplaceAll(key, ".", "/")))
}

func (s *Sysctl) read(key string) (string, error) {
	if s.ReadValue != nil {
		v, err := s.ReadValue(key)
		return strings.TrimSpace(v), err
	}
	data, err := os.ReadFile(s.path(key))
	return strings.TrimSpace(string(data)), err
}

func (s *Sysctl) write(key, value string) error {
	if s.WriteValue != nil {
		return s.WriteValue(key, value)
	}
	return os.WriteFile(s.path(key), []byte(value), 0o644)
}

// Set makes key equal to enabled ("1"/"0"). Disabling only restores what Set
// changed; it never turns off a setting this process did not turn on.
func (s *Sysctl) Set(key string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.previous == nil {
		s.previous = map[string]string{}
	}
	current, err := s.read(key)
	if err != nil {
		return fmt.Errorf("read %s: %w", key, err)
	}
	previous, owned := s.previous[key]
	if enabled {
		if current == "1" {
			return nil
		}
		if !owned {
			s.previous[key] = current
		}
		if err := s.write(key, "1"); err != nil {
			return fmt.Errorf("enable %s: %w", key, err)
		}
		return nil
	}
	if !owned {
		return nil
	}
	if current == "1" {
		if err := s.write(key, previous); err != nil {
			return fmt.Errorf("restore %s: %w", key, err)
		}
	}
	delete(s.previous, key)
	return nil
}

// Owned reports whether key was changed by this process.
func (s *Sysctl) Owned(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.previous[key]
	return ok
}

const (
	SysctlIPv4 = "net.ipv4.ip_forward"
	SysctlIPv6 = "net.ipv6.conf.all.forwarding"
)

// LinkForwarding owns per-interface forwarding flags (Windows). Like Sysctl
// it only turns off what it turned on, and only while it is still on.
type LinkForwarding struct {
	Get   func(link int, v6 bool) (bool, error)
	Set   func(link int, v6, on bool) error
	owned map[linkFamily]bool
}

type linkFamily struct {
	link int
	v6   bool
}

// Apply enables forwarding on want and turns it off again on links this
// owner enabled that are no longer wanted.
func (l *LinkForwarding) Apply(want map[int]bool, v4, v6 bool) error {
	if l.owned == nil {
		l.owned = map[linkFamily]bool{}
	}
	desired := map[linkFamily]bool{}
	for link := range want {
		if link <= 0 {
			continue
		}
		if v4 {
			desired[linkFamily{link, false}] = true
		}
		if v6 {
			desired[linkFamily{link, true}] = true
		}
	}
	var result error
	for k := range desired {
		if _, done := l.owned[k]; done {
			continue
		}
		on, err := l.Get(k.link, k.v6)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if on {
			// Already forwarding: not ours to turn off later.
			l.owned[k] = false
			continue
		}
		if err := l.Set(k.link, k.v6, true); err != nil {
			result = errors.Join(result, err)
			continue
		}
		l.owned[k] = true
	}
	for k, changed := range l.owned {
		if desired[k] {
			continue
		}
		if changed {
			on, err := l.Get(k.link, k.v6)
			if err == nil && on {
				err = l.Set(k.link, k.v6, false)
			}
			if err != nil && !errors.Is(err, ErrLinkGone) {
				result = errors.Join(result, err)
				continue
			}
		}
		delete(l.owned, k)
	}
	return result
}

// ErrLinkGone is returned by LinkForwarding.Get/Set for removed interfaces.
var ErrLinkGone = errors.New("interface no longer exists")
