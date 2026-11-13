package inbound

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync/atomic"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"go4.org/netipx"
)

// MaxGeneratedTunRoutes bounds the routes one routing mode may install. Larger
// results are rejected rather than partially installed.
const MaxGeneratedTunRoutes = 16384

// GeoIPPrefixSource resolves country codes of the loaded GeoIP database.
type GeoIPPrefixSource interface {
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
	// Loopback never uses a TUN. ::/16 holds only the unspecified, loopback,
	// IPv4-compatible and IPv4-mapped addresses (NAT64 64:ff9b::/96 is
	// outside it); excluding the aligned block avoids ~128 routes that
	// excluding ::/128 and ::1/128 individually would need.
	tunNeverRouted = mustPrefixes("127.0.0.0/8", "::/16")
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

// TunRoutingExclusions returns the built-in networks a mode keeps off the
// TUN. Loopback is never routed in any mode.
func TunRoutingExclusions(mode string) []netip.Prefix {
	out := append([]netip.Prefix(nil), tunNeverRouted...)
	switch mode {
	case contract.TunRouteModeGlobal:
		out = append(out, globalExclusions...)
	case contract.TunRouteModeNonPrivate, contract.TunRouteModeCustom:
		out = append(out, globalExclusions...)
		out = append(out, privateExclusions...)
	}
	return out
}

// GenerateTunRoutes resolves a routing mode to the minimal set of prefixes to
// route to the TUN, for both address families:
//
//	routes = ((base - built-in exclusions) ∪ include) - bypass - loopback
//
// base is everything for global and non_private, and global ignores include
// (its exclusions are never internet traffic). For custom it is the
// selected countries, or with GeoIPInvert the public internet (everything
// except the non_private exclusions) minus the selected countries. Custom
// include CIDRs are used as given, so private networks can be routed
// explicitly. Duplicates, contained and adjacent prefixes are merged, and
// set differences are exact. A /0 result is split into two /1 routes so the
// system default route stays intact.
func GenerateTunRoutes(routing contract.TunRouting, geoip GeoIPPrefixSource) ([]netip.Prefix, error) {
	if err := routing.Validate(); err != nil {
		return nil, err
	}
	if !routing.Managed() {
		return nil, errors.New("TUN routing mode is not set")
	}
	include, _ := contract.ParseTunRoutingCIDRs("include", routing.IncludeCIDRs)
	bypass, _ := contract.ParseTunRoutingCIDRs("bypass", routing.BypassCIDRs)
	countries, _ := contract.NormalizeTunCountries(routing.GeoIPCountries)

	var b netipx.IPSetBuilder
	switch routing.Mode {
	case contract.TunRouteModeGlobal:
		addAll(&b, allAddresses)
		removeAll(&b, TunRoutingExclusions(routing.Mode))
		// Global has nothing to add back; only bypass applies.
		include = nil
	case contract.TunRouteModeNonPrivate:
		addAll(&b, allAddresses)
		removeAll(&b, TunRoutingExclusions(routing.Mode))
	case contract.TunRouteModeCustom:
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
		if routing.GeoIPInvert {
			addAll(&b, allAddresses)
			removeAll(&b, TunRoutingExclusions(contract.TunRouteModeNonPrivate))
			removeAll(&b, geo)
		} else {
			addAll(&b, geo)
		}
	}
	addAll(&b, include)
	removeAll(&b, bypass)
	removeAll(&b, tunNeverRouted)
	set, err := b.IPSet()
	if err != nil {
		return nil, err
	}
	routes := splitDefaultRoutes(set.Prefixes())
	if len(routes) > MaxGeneratedTunRoutes {
		return nil, fmt.Errorf("TUN routing generates %d routes, more than the limit of %d; select fewer countries or use broader CIDRs", len(routes), MaxGeneratedTunRoutes)
	}
	return routes, nil
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

func splitDefaultRoutes(routes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(routes)+2)
	for _, p := range routes {
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

// runtimeTun returns req with TUN routes generated from its routing mode.
// The stored configuration is unchanged; generated routes are runtime state.
// On error the TUN captures no generated routes, so traffic keeps using the
// system routes until generation succeeds.
func runtimeTun(req contract.Inbound, geoip GeoIPPrefixSource) (contract.Inbound, error) {
	if req.Protocol.Type != contract.ProtocolTun || req.Protocol.Tun == nil || !req.Protocol.Tun.Routing.Managed() {
		return req, nil
	}
	tun := *req.Protocol.Tun
	routes, err := GenerateTunRoutes(tun.Routing, geoip)
	tun.Routes = make([]string, len(routes))
	for i, p := range routes {
		tun.Routes[i] = p.String()
	}
	tun.Excludes = nil
	req.Protocol.Tun = &tun
	if err != nil {
		err = fmt.Errorf("generate TUN routes for %q: %w", req.Name, err)
	}
	return req, err
}

// usesGeoIP reports whether a TUN's routes depend on the GeoIP database.
func usesGeoIP(config *contract.Inbound) bool {
	return config != nil && config.Protocol.Tun != nil && config.Protocol.Tun.Routing.Mode == contract.TunRouteModeCustom &&
		len(config.Protocol.Tun.Routing.GeoIPCountries) != 0
}

// WithGeoIPPrefixSource supplies the GeoIP database used by custom TUN
// routing. Without it, GeoIP country routing reports ErrGeoIPUnavailable.
func WithGeoIPPrefixSource(source GeoIPPrefixSource) Option {
	return func(l *Inbound) { l.geoip = source }
}

type tunRouteSetter interface {
	SetRoutes(routes []netip.Prefix, managed bool) error
}

// tunRoutesOnlyChanged reports whether two TUN inbounds differ only in their
// route selection, and the new one uses a routing mode.
func tunRoutesOnlyChanged(old, req contract.Inbound) bool {
	if old.Protocol.Tun == nil || req.Protocol.Tun == nil || !req.Protocol.Tun.Routing.Managed() {
		return false
	}
	strip := func(in contract.Inbound) contract.Inbound {
		tun := *in.Protocol.Tun
		tun.Routes, tun.Excludes, tun.Routing = nil, nil, contract.TunRouting{}
		in.Protocol.Tun = &tun
		return in
	}
	return reflect.DeepEqual(strip(old), strip(req))
}

// applyTunRoutes installs the generated routes of runtimeReq on a running
// TUN without rebuilding it. handled is false when server cannot do that.
func applyTunRoutes(server netapi.Accepter, runtimeReq contract.Inbound, generateErr error) (handled bool, err error) {
	tun := runtimeReq.Protocol.Tun
	switch s := server.(type) {
	case tunRouteSetter:
		routes := make([]netip.Prefix, 0, len(tun.Routes))
		for _, route := range tun.Routes {
			routes = append(routes, netip.MustParsePrefix(route))
		}
		return true, errors.Join(generateErr, s.SetRoutes(routes, true))
	case *platformTunAccepter:
		if s.Generation() == 0 {
			return false, nil
		}
		return true, errors.Join(generateErr, s.Reconfigure(platformSpec(*tun)))
	}
	return false, nil
}

// RefreshTunRoutes regenerates the routes of running TUNs that use a routing
// mode, in place. With geoipOnly only TUNs that select GeoIP countries are
// refreshed (after a GeoIP database update). Otherwise every desktop TUN
// re-synchronizes its routes, which also retries prefixes skipped because of
// conflicting system routes (after a network change).
func (l *Inbound) RefreshTunRoutes(geoipOnly bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	var result error
	for key, entry := range l.store.Range {
		config := entry.contractConfig
		if config == nil || config.Protocol.Tun == nil || !config.Protocol.Tun.Routing.Managed() || entry.server == nil {
			continue
		}
		if geoipOnly && !usesGeoIP(config) {
			continue
		}
		if _, desktop := entry.server.(tunRouteSetter); !geoipOnly && !desktop {
			continue
		}
		runtimeReq, generateErr := runtimeTun(*config, l.geoip)
		handled, err := applyTunRoutes(entry.server, runtimeReq, generateErr)
		if !handled {
			continue
		}
		if err != nil {
			log.Error("refresh TUN routes failed", "name", config.Name, "err", err)
			l.recordState(key, "degraded", err.Error())
			result = errors.Join(result, err)
		} else {
			l.recordState(key, "running", "")
		}
	}
	return result
}

// watchNetworkForTunRoutes re-synchronizes desktop TUN routes after network
// changes. Bursts are coalesced into one refresh at a time.
func (l *Inbound) watchNetworkForTunRoutes() {
	var running atomic.Bool
	var again atomic.Bool
	closer := interfaces.AddNetworkMonitor(func(string) {
		again.Store(true)
		if !running.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer running.Store(false)
			for again.Swap(false) {
				if err := l.RefreshTunRoutes(false); err != nil {
					log.Warn("resync TUN routes after network change failed", "err", err)
				}
			}
		}()
	})
	l.stopNetworkWatch = func() { _ = closer.Close() }
}
