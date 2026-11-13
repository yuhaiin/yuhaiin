// Package sysnet defines the System Network configuration: operating system
// routes towards Yuhaiin TUNs or other interfaces, and Linux forwarding.
//
// Config is the saved desired state. Status is runtime state reported by the
// manager: what was applied to the operating system and why something was not.
// The two are never mixed in one document.
package sysnet

import (
	"fmt"
	"net/netip"
	"strings"
)

// Match modes.
const (
	ModeGlobal     = "global"
	ModeNonPrivate = "non_private"
	ModeCustom     = "custom"
)

// Target types. TProxy is an interception action of forwarding, not a route
// target: it is only valid as a forwarding egress on Linux. Routes is a
// forwarding egress meaning "follow the system routing table", which already
// includes the System Network route rules.
const (
	TargetTunInbound = "tun_inbound"
	TargetInterface  = "interface"
	TargetTProxy     = "tproxy"
	TargetRoutes     = "routes"
)

// Bounds for user input. Generated routes have a separate runtime limit.
const (
	MaxRules     = 256
	MaxCIDRs     = 4096
	MaxCountries = 256
	MaxPriority  = 65535
)

// Config is the saved System Network configuration.
type Config struct {
	Routes     []RouteRule `json:"routes"`
	Forwarding Forwarding  `json:"forwarding"`
	// Migrations records TUN inbound route settings converted into rules. It
	// is informational and maintained by the core, not by API clients.
	Migrations []Migration `json:"migrations,omitzero"`
}

// RouteRule routes the destinations of Match to Target. Rules are evaluated
// by ascending Priority (then position); the first enabled, available rule
// matching a destination owns it, so every prefix has exactly one target.
type RouteRule struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	Enabled  bool        `json:"enabled"`
	Priority int         `json:"priority"`
	Match    RouteMatch  `json:"match"`
	Target   RouteTarget `json:"target"`
}

// RouteMatch selects destinations. Bypass always wins over include, and
// include wins over the built-in exclusions of a mode.
type RouteMatch struct {
	Mode string `json:"mode"`
	// IncludeCIDRs are the destinations of the custom mode, or networks added
	// back from the built-in exclusions of non_private. Global ignores them.
	IncludeCIDRs []string `json:"includeCidrs,omitzero"`
	BypassCIDRs  []string `json:"bypassCidrs,omitzero"`
	// GeoIPCountries are country codes of the loaded MaxMind database (custom
	// mode). GeoIPInvert selects the public internet except those countries.
	GeoIPCountries []string `json:"geoipCountries,omitzero"`
	GeoIPInvert    bool     `json:"geoipInvert,omitzero"`
}

// RouteTarget identifies where traffic goes. Interface indexes are runtime
// state: a Yuhaiin TUN is identified by its inbound ID and other interfaces by
// name (with the hardware address as a fallback after a rename).
type RouteTarget struct {
	Type          string `json:"type"`
	InboundID     string `json:"inboundId,omitzero"`
	InterfaceName string `json:"interfaceName,omitzero"`
	HardwareAddr  string `json:"hardwareAddr,omitzero"`
	// Gateway and GatewayV6 override gateway detection for broadcast
	// interfaces such as Ethernet or Wi-Fi. Point-to-point interfaces need none.
	Gateway   string `json:"gateway,omitzero"`
	GatewayV6 string `json:"gatewayV6,omitzero"`
}

// Forwarding configures routing of traffic that other devices send through
// this host (side router). Enabling IPv4 or IPv6 turns on kernel forwarding
// for that family; rules select which traffic leaves through which target.
type Forwarding struct {
	IPv4  bool          `json:"ipv4"`
	IPv6  bool          `json:"ipv6"`
	Rules []ForwardRule `json:"rules"`
}

// ForwardRule sends traffic arriving on IngressInterface from SourceCIDRs (and
// optionally only to DestinationCIDRs) out through Egress. Empty SourceCIDRs
// mean every device on the ingress; platforms without source filtering
// (Windows) only accept that. Masquerade rewrites the source address to the
// egress address, for upstreams without a return route to the LAN.
type ForwardRule struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Enabled          bool        `json:"enabled"`
	IngressInterface string      `json:"ingressInterface"`
	SourceCIDRs      []string    `json:"sourceCidrs"`
	DestinationCIDRs []string    `json:"destinationCidrs,omitzero"`
	Egress           RouteTarget `json:"egress"`
	Masquerade       bool        `json:"masquerade,omitzero"`
}

// Migration records one TUN inbound whose route settings became a rule.
type Migration struct {
	InboundID   string   `json:"inboundId"`
	InboundName string   `json:"inboundName"`
	RuleID      string   `json:"ruleId,omitzero"`
	Source      string   `json:"source"`
	Warnings    []string `json:"warnings,omitzero"`
	MigratedAt  int64    `json:"migratedAt"`
}

func (c Config) Validate() error {
	if len(c.Routes) > MaxRules || len(c.Forwarding.Rules) > MaxRules {
		return fmt.Errorf("too many System Network rules (maximum %d)", MaxRules)
	}
	ids := map[string]bool{}
	for i, rule := range c.Routes {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("route rule #%d %q: %w", i+1, rule.Name, err)
		}
		if ids[rule.ID] {
			return fmt.Errorf("route rule #%d: duplicate id %q", i+1, rule.ID)
		}
		ids[rule.ID] = true
	}
	for i, rule := range c.Forwarding.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("forwarding rule #%d %q: %w", i+1, rule.Name, err)
		}
		if ids[rule.ID] {
			return fmt.Errorf("forwarding rule #%d: duplicate id %q", i+1, rule.ID)
		}
		ids[rule.ID] = true
	}
	return nil
}

func validID(id string) error {
	if id == "" || len(id) > 128 || strings.TrimSpace(id) != id {
		return fmt.Errorf("invalid id %q", id)
	}
	return nil
}

func (r RouteRule) Validate() error {
	if err := validID(r.ID); err != nil {
		return err
	}
	if len(r.Name) > 128 {
		return fmt.Errorf("name is longer than 128 characters")
	}
	if r.Priority < 0 || r.Priority > MaxPriority {
		return fmt.Errorf("priority must be between 0 and %d", MaxPriority)
	}
	if err := r.Match.Validate(); err != nil {
		return err
	}
	if r.Target.Type == TargetTProxy {
		return fmt.Errorf("TProxy is a forwarding action, not a route target")
	}
	return r.Target.Validate()
}

// Validate checks every field, including fields the selected mode ignores:
// they are kept so switching modes in the editor loses nothing.
func (m RouteMatch) Validate() error {
	switch m.Mode {
	case ModeGlobal, ModeNonPrivate:
	case ModeCustom:
		if len(m.IncludeCIDRs) == 0 && len(m.GeoIPCountries) == 0 && !m.GeoIPInvert {
			return fmt.Errorf("custom routing requires CIDRs or GeoIP countries")
		}
	default:
		return fmt.Errorf("unknown match mode %q", m.Mode)
	}
	if _, err := ParseCIDRs("include", m.IncludeCIDRs); err != nil {
		return err
	}
	if _, err := ParseCIDRs("bypass", m.BypassCIDRs); err != nil {
		return err
	}
	_, err := NormalizeCountries(m.GeoIPCountries)
	return err
}

func (t RouteTarget) Validate() error {
	switch t.Type {
	case TargetTunInbound, TargetTProxy:
		if strings.TrimSpace(t.InboundID) == "" {
			return fmt.Errorf("target requires an inbound")
		}
	case TargetInterface:
		if strings.TrimSpace(t.InterfaceName) == "" {
			return fmt.Errorf("target requires an interface")
		}
	default:
		return fmt.Errorf("unknown target type %q", t.Type)
	}
	if t.Gateway != "" {
		if a, err := netip.ParseAddr(t.Gateway); err != nil || !a.Is4() {
			return fmt.Errorf("invalid IPv4 gateway %q", t.Gateway)
		}
	}
	if t.GatewayV6 != "" {
		if a, err := netip.ParseAddr(t.GatewayV6); err != nil || !a.Is6() || a.Is4In6() {
			return fmt.Errorf("invalid IPv6 gateway %q", t.GatewayV6)
		}
	}
	return nil
}

func (r ForwardRule) Validate() error {
	if err := validID(r.ID); err != nil {
		return err
	}
	if len(r.Name) > 128 {
		return fmt.Errorf("name is longer than 128 characters")
	}
	if strings.TrimSpace(r.IngressInterface) == "" {
		return fmt.Errorf("ingress interface is required")
	}
	if _, err := ParseCIDRs("source", r.SourceCIDRs); err != nil {
		return err
	}
	if _, err := ParseCIDRs("destination", r.DestinationCIDRs); err != nil {
		return err
	}
	if r.Egress.Type == TargetTProxy && r.Masquerade {
		return fmt.Errorf("masquerade does not apply to TProxy interception")
	}
	if r.Egress.Type == TargetRoutes {
		if r.Masquerade {
			return fmt.Errorf("masquerade needs an egress interface")
		}
		return nil
	}
	return r.Egress.Validate()
}

// ParseCIDRs parses CIDRs or single addresses and rejects invalid entries
// instead of ignoring them.
func ParseCIDRs(field string, values []string) ([]netip.Prefix, error) {
	if len(values) > MaxCIDRs {
		return nil, fmt.Errorf("too many %s CIDRs: %d (maximum %d)", field, len(values), MaxCIDRs)
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for i, value := range values {
		p, err := ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("%s CIDR #%d %q: %w", field, i+1, value, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// ParseCIDR accepts "192.0.2.0/24", "2001:db8::/32" or a single address.
// Host bits are masked: 192.0.2.1/24 means 192.0.2.0/24.
func ParseCIDR(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("empty CIDR")
	}
	if strings.Contains(value, "/") {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR")
		}
		if p.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("zones are not allowed")
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil || addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid IP address or CIDR")
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// NormalizeCountries upper-cases, trims and deduplicates country codes. Codes
// are not checked against ISO 3166 because databases may contain custom
// values such as "LAN".
func NormalizeCountries(values []string) ([]string, error) {
	if len(values) > MaxCountries {
		return nil, fmt.Errorf("too many GeoIP countries: %d (maximum %d)", len(values), MaxCountries)
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		code := strings.ToUpper(strings.TrimSpace(value))
		if code == "" || len(code) > 16 || strings.IndexFunc(code, func(r rune) bool {
			return (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-'
		}) >= 0 {
			return nil, fmt.Errorf("invalid GeoIP country code %q", value)
		}
		if !seen[code] {
			seen[code] = true
			out = append(out, code)
		}
	}
	return out, nil
}
