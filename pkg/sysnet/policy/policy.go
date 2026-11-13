// Package policy turns System Network route rules into exact, non-overlapping
// prefix sets. It is pure: no operating system access, so the same results are
// used by every platform adapter and by the editor preview.
package policy

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"go4.org/netipx"
)

// Limits on generated routes. Larger results are rejected rather than
// installed partly.
const (
	MaxRoutesPerRule = 16384
	MaxRoutes        = 32768
)

// GeoIPSource resolves country codes of the loaded GeoIP database.
type GeoIPSource interface {
	PrefixesByCountries(countries []string) ([]netip.Prefix, error)
}

// ErrGeoIPUnavailable is returned while no GeoIP database is loaded.
var ErrGeoIPUnavailable = errors.New("GeoIP database is not loaded; configure and refresh the MaxMind GeoIP database in routing list settings")

func mustPrefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(values))
	for i, v := range values {
		out[i] = netip.MustParsePrefix(v)
	}
	return out
}

var (
	allAddresses = mustPrefixes("0.0.0.0/0", "::/0")
	// Loopback is never routed. ::/16 holds only the unspecified, loopback,
	// IPv4-compatible and IPv4-mapped addresses (NAT64 64:ff9b::/96 is
	// outside it); excluding the aligned block avoids ~128 routes that
	// excluding ::/128 and ::1/128 individually would need.
	neverRouted = mustPrefixes("127.0.0.0/8", "::/16")
	// Global keeps "this network", link-local, multicast and the reserved
	// 240.0.0.0/4 (which includes broadcast) on the local link: they are not
	// internet traffic and capturing them breaks DHCP, mDNS and NDP.
	globalExclusions = mustPrefixes(
		"0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3",
		"fe80::/10", "ff00::/8",
	)
	// Non-private additionally keeps private (RFC 1918), shared address
	// space (RFC 6598 CGNAT, used by Tailscale) and unique local IPv6 (also
	// used by Tailscale). Documentation and benchmarking ranges never appear
	// on the internet, and excluding them would only add routes; 198.18.0.0/15
	// is also the usual FakeIP pool.
	privateExclusions = mustPrefixes(
		"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16",
		"fc00::/7",
	)
)

// Exclusions returns the built-in networks a mode keeps off its target.
// Loopback is excluded in every mode.
func Exclusions(mode string) []netip.Prefix {
	out := append([]netip.Prefix(nil), neverRouted...)
	switch mode {
	case sysnet.ModeGlobal:
		out = append(out, globalExclusions...)
	case sysnet.ModeNonPrivate, sysnet.ModeCustom:
		out = append(out, globalExclusions...)
		out = append(out, privateExclusions...)
	}
	return out
}

// Generate resolves a match to the exact destination set, for both families:
//
//	set = ((base - built-in exclusions) ∪ include) - bypass - loopback
//
// base is everything for global and non_private; global ignores include
// (its exclusions are never internet traffic). For custom it is the selected
// countries, or with GeoIPInvert the public internet (everything except the
// non_private exclusions) minus the selected countries. Custom include CIDRs
// are used as given, so private networks can be routed explicitly.
func Generate(match sysnet.RouteMatch, geoip GeoIPSource) (*netipx.IPSet, error) {
	if err := match.Validate(); err != nil {
		return nil, err
	}
	include, _ := sysnet.ParseCIDRs("include", match.IncludeCIDRs)
	bypass, _ := sysnet.ParseCIDRs("bypass", match.BypassCIDRs)
	countries, _ := sysnet.NormalizeCountries(match.GeoIPCountries)

	var b netipx.IPSetBuilder
	switch match.Mode {
	case sysnet.ModeGlobal:
		addAll(&b, allAddresses)
		removeAll(&b, Exclusions(match.Mode))
		include = nil
	case sysnet.ModeNonPrivate:
		addAll(&b, allAddresses)
		removeAll(&b, Exclusions(match.Mode))
	case sysnet.ModeCustom:
		var geo []netip.Prefix
		if len(countries) != 0 {
			if geoip == nil {
				return nil, ErrGeoIPUnavailable
			}
			var err error
			if geo, err = geoip.PrefixesByCountries(countries); err != nil {
				return nil, fmt.Errorf("resolve GeoIP countries: %w", err)
			}
		}
		if match.GeoIPInvert {
			addAll(&b, allAddresses)
			removeAll(&b, Exclusions(sysnet.ModeNonPrivate))
			removeAll(&b, geo)
		} else {
			addAll(&b, geo)
		}
	}
	addAll(&b, include)
	removeAll(&b, bypass)
	removeAll(&b, neverRouted)
	return b.IPSet()
}

// UsesGeoIP reports whether a match depends on the GeoIP database.
func UsesGeoIP(match sysnet.RouteMatch) bool {
	return match.Mode == sysnet.ModeCustom && len(match.GeoIPCountries) != 0
}

func addAll(b *netipx.IPSetBuilder, prefixes []netip.Prefix) {
	for _, p := range prefixes {
		b.AddPrefix(p)
	}
}

func removeAll(b *netipx.IPSetBuilder, prefixes []netip.Prefix) {
	for _, p := range prefixes {
		b.RemovePrefix(p)
	}
}

// Routes returns the minimal prefixes of set, with a /0 split into two /1
// routes so the system default route stays intact.
func Routes(set *netipx.IPSet) []netip.Prefix {
	if set == nil {
		return nil
	}
	prefixes := set.Prefixes()
	out := make([]netip.Prefix, 0, len(prefixes)+2)
	for _, p := range prefixes {
		if p.Bits() != 0 {
			out = append(out, p)
			continue
		}
		low := netip.PrefixFrom(p.Addr(), 1)
		high := netipx.PrefixLastIP(low).Next()
		out = append(out, low, netip.PrefixFrom(high, 1))
	}
	return out
}

// Candidate is one rule's generated destination set, in evaluation order.
type Candidate struct {
	ID  string
	Set *netipx.IPSet
}

// Assignment is what a rule owns after higher-priority rules took theirs.
type Assignment struct {
	ID string
	// Set is the rule's destinations minus everything assigned before it.
	Set *netipx.IPSet
	// OverriddenBy are earlier candidates sharing destinations with this one.
	OverriddenBy []string
	// Shadowed is set when earlier candidates take every destination.
	Shadowed bool
}

// Resolve assigns destinations first-match: candidates are evaluated in
// order and each one loses whatever an earlier candidate already owns. The
// results never overlap, so one prefix is never sent to two targets, and the
// configured order — not the operating system's longest-prefix match —
// decides which target wins.
func Resolve(candidates []Candidate) ([]Assignment, error) {
	var assigned netipx.IPSetBuilder
	out := make([]Assignment, 0, len(candidates))
	for i, c := range candidates {
		a := Assignment{ID: c.ID}
		if c.Set == nil {
			out = append(out, a)
			continue
		}
		for _, earlier := range candidates[:i] {
			if earlier.Set != nil && earlier.Set.Overlaps(c.Set) {
				a.OverriddenBy = append(a.OverriddenBy, earlier.ID)
			}
		}
		taken, err := assigned.IPSet()
		if err != nil {
			return nil, err
		}
		var own netipx.IPSetBuilder
		own.AddSet(c.Set)
		own.RemoveSet(taken)
		if a.Set, err = own.IPSet(); err != nil {
			return nil, err
		}
		a.Shadowed = len(c.Set.Ranges()) != 0 && len(a.Set.Ranges()) == 0
		assigned.AddSet(c.Set)
		out = append(out, a)
	}
	return out, nil
}

// SetOf builds a set from prefixes.
func SetOf(prefixes []netip.Prefix) *netipx.IPSet {
	var b netipx.IPSetBuilder
	addAll(&b, prefixes)
	set, _ := b.IPSet()
	return set
}

// Families counts IPv4 and IPv6 prefixes.
func Families(prefixes []netip.Prefix) (v4, v6 int) {
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4++
		} else {
			v6++
		}
	}
	return
}

// RuleRoutes generates a match and returns its routes, enforcing the per-rule
// route limit.
func RuleRoutes(match sysnet.RouteMatch, geoip GeoIPSource) ([]netip.Prefix, error) {
	set, err := Generate(match, geoip)
	if err != nil {
		return nil, err
	}
	routes := Routes(set)
	if len(routes) > MaxRoutesPerRule {
		return nil, fmt.Errorf("rule generates %d routes, more than the limit of %d; select fewer countries or use broader CIDRs", len(routes), MaxRoutesPerRule)
	}
	return routes, nil
}
