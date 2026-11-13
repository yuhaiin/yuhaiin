package inbound

import (
	"fmt"
	"net/netip"
	"strings"
)

// TUN routing modes. An empty mode keeps the legacy routes/excludes lists.
const (
	TunRouteModeLegacy     = ""
	TunRouteModeGlobal     = "global"
	TunRouteModeNonPrivate = "non_private"
	TunRouteModeCustom     = "custom"
)

// Bounds for user input. Generated routes have a separate runtime limit.
const (
	MaxTunRoutingCIDRs     = 4096
	MaxTunRoutingCountries = 256
)

// TunRouting selects the destinations a TUN captures.
//
// Include networks are routed to the TUN; bypass networks keep the system's
// original routes. Bypass always wins over include, and include wins over the
// built-in exclusions of a mode. The same result is installed on desktop route
// tables and on the Android VpnService.
type TunRouting struct {
	Mode string `json:"mode,omitzero"`
	// IncludeCIDRs are the routes of the custom mode, or the networks added
	// back to the TUN from the built-in exclusions of non_private.
	IncludeCIDRs []string `json:"includeCidrs,omitzero"`
	BypassCIDRs  []string `json:"bypassCidrs,omitzero"`
	// GeoIPCountries are country codes of the loaded MaxMind database (custom
	// mode). GeoIPInvert routes the public internet except those countries.
	GeoIPCountries []string `json:"geoipCountries,omitzero"`
	GeoIPInvert    bool     `json:"geoipInvert,omitzero"`
}

// Managed reports whether routes are generated from the routing mode instead
// of the legacy routes/excludes lists.
func (r TunRouting) Managed() bool { return r.Mode != TunRouteModeLegacy }

// Validate checks every field, including fields the selected mode ignores:
// they are kept so switching modes in the editor loses nothing. Global uses
// only BypassCIDRs, non_private uses IncludeCIDRs and BypassCIDRs, custom
// uses all fields, and the legacy mode ignores all of them.
func (r TunRouting) Validate() error {
	switch r.Mode {
	case TunRouteModeLegacy, TunRouteModeGlobal, TunRouteModeNonPrivate:
	case TunRouteModeCustom:
		if len(r.IncludeCIDRs) == 0 && len(r.GeoIPCountries) == 0 && !r.GeoIPInvert {
			return fmt.Errorf("custom TUN routing requires CIDRs or GeoIP countries")
		}
	default:
		return fmt.Errorf("unknown TUN routing mode %q", r.Mode)
	}
	if _, err := ParseTunRoutingCIDRs("include", r.IncludeCIDRs); err != nil {
		return err
	}
	if _, err := ParseTunRoutingCIDRs("bypass", r.BypassCIDRs); err != nil {
		return err
	}
	_, err := NormalizeTunCountries(r.GeoIPCountries)
	return err
}

// ParseTunRoutingCIDRs parses CIDRs or single addresses. Unlike the legacy
// lists, invalid entries are rejected instead of ignored.
func ParseTunRoutingCIDRs(field string, values []string) ([]netip.Prefix, error) {
	if len(values) > MaxTunRoutingCIDRs {
		return nil, fmt.Errorf("too many TUN %s CIDRs: %d (maximum %d)", field, len(values), MaxTunRoutingCIDRs)
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for i, value := range values {
		p, err := ParseTunCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("TUN %s CIDR #%d %q: %w", field, i+1, value, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// ParseTunCIDR accepts "192.0.2.0/24", "2001:db8::/32" or a single address.
// Host bits are masked: 192.0.2.1/24 means 192.0.2.0/24.
func ParseTunCIDR(value string) (netip.Prefix, error) {
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

// NormalizeTunCountries upper-cases, trims and deduplicates country codes.
// Codes are not checked against ISO 3166 because databases may contain
// custom values such as "LAN".
func NormalizeTunCountries(values []string) ([]string, error) {
	if len(values) > MaxTunRoutingCountries {
		return nil, fmt.Errorf("too many TUN GeoIP countries: %d (maximum %d)", len(values), MaxTunRoutingCountries)
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		code := strings.ToUpper(strings.TrimSpace(value))
		if code == "" || len(code) > 16 || strings.IndexFunc(code, func(r rune) bool {
			return (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-'
		}) >= 0 {
			return nil, fmt.Errorf("invalid TUN GeoIP country code %q", value)
		}
		if !seen[code] {
			seen[code] = true
			out = append(out, code)
		}
	}
	return out, nil
}
