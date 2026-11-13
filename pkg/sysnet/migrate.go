package sysnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

// HasLegacyRouting reports whether a TUN inbound still carries route settings
// from before the System Network Manager.
func HasLegacyRouting(in contractinbound.Inbound) bool {
	tun := in.Protocol.Tun
	return tun != nil && (tun.Routing.Mode != "" || len(tun.Routing.IncludeCIDRs)+len(tun.Routing.BypassCIDRs)+len(tun.Routing.GeoIPCountries) != 0 ||
		tun.Routing.GeoIPInvert || len(tun.Routes) != 0 || len(tun.Excludes) != 0)
}

// ClearLegacyRouting returns in without its legacy route settings.
func ClearLegacyRouting(in contractinbound.Inbound) contractinbound.Inbound {
	if in.Protocol.Tun == nil {
		return in
	}
	tun := *in.Protocol.Tun
	tun.Routes, tun.Excludes, tun.Routing = nil, nil, contractinbound.TunRouting{}
	in.Protocol.Tun = &tun
	return in
}

// legacyEntries expands legacy route entries the way TUNs used to: CIDRs,
// single addresses and "file:" lists; invalid entries were silently ignored
// and are now reported as warnings.
func legacyEntries(values []string, readFile func(string) ([]byte, error), warnings *[]string) []string {
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		p, err := sysnet.ParseCIDR(v)
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("ignored invalid route %q, as earlier versions did", v))
			return
		}
		out = append(out, p.String())
	}
	for _, v := range values {
		path, ok := strings.CutPrefix(v, "file:")
		if !ok {
			add(v)
			continue
		}
		data, err := readFile(path)
		if err != nil {
			*warnings = append(*warnings, fmt.Sprintf("route list %s could not be read: %v", path, err))
			continue
		}
		*warnings = append(*warnings, fmt.Sprintf("routes from %s were copied; later changes to the file are not followed", path))
		for line := range strings.Lines(string(data)) {
			add(line)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// MigrateLegacy converts the legacy route settings of TUN inbounds into rules
// targeting those TUNs, preserving their earlier behavior on goos:
//
//   - A routing mode (global, non_private, custom) becomes the same match.
//   - Manual lists: desktop installed routes and excludes alike as routes,
//     so both become include CIDRs of a custom rule. Android excluded the
//     excludes (API 33+), so they become bypass CIDRs; with no routes Android
//     used its own route profile and excludes were unused, so no rule is made.
//
// Rule IDs derive from the inbound and its settings, so repeating a migration
// never duplicates rules. Rules of different TUNs that overlap are kept; their
// order follows the inbound order and conflicts show in the status. It
// returns the updated configuration and the inbounds whose legacy settings
// can now be cleared.
func MigrateLegacy(config sysnet.Config, inbounds []contractinbound.Inbound, goos string, readFile func(string) ([]byte, error), now time.Time) (sysnet.Config, []string) {
	var cleared []string
	priority := 1000
	for _, r := range config.Routes {
		priority = max(priority, r.Priority+10)
	}
	ids := map[string]bool{}
	for _, r := range config.Routes {
		ids[r.ID] = true
	}
	sorted := slices.Clone(inbounds)
	slices.SortFunc(sorted, func(a, b contractinbound.Inbound) int { return strings.Compare(a.ID, b.ID) })
	for _, in := range sorted {
		if in.Protocol.Type != contractinbound.ProtocolTun || !HasLegacyRouting(in) {
			continue
		}
		tun := in.Protocol.Tun
		record := sysnet.Migration{InboundID: in.ID, InboundName: in.Name, MigratedAt: now.Unix()}
		var match *sysnet.RouteMatch
		switch {
		case tun.Routing.Mode != "":
			m := sysnet.RouteMatch{Mode: tun.Routing.Mode, IncludeCIDRs: tun.Routing.IncludeCIDRs, BypassCIDRs: tun.Routing.BypassCIDRs,
				GeoIPCountries: tun.Routing.GeoIPCountries, GeoIPInvert: tun.Routing.GeoIPInvert}
			record.Source = "tun_routing:" + m.Mode
			if len(tun.Routes)+len(tun.Excludes) != 0 {
				record.Warnings = append(record.Warnings, "manual route lists were not in use with a routing mode and were not migrated")
			}
			if err := m.Validate(); err != nil {
				record.Warnings = append(record.Warnings, "routing mode could not be migrated: "+err.Error())
			} else {
				match = &m
			}
		case goos == "android":
			record.Source = "routes"
			include := legacyEntries(tun.Routes, readFile, &record.Warnings)
			if len(include) == 0 {
				if len(tun.Excludes) != 0 {
					record.Warnings = append(record.Warnings, "excluded routes were unused without routes (the Android route profile applied) and were not migrated")
				}
				break
			}
			m := sysnet.RouteMatch{Mode: sysnet.ModeCustom, IncludeCIDRs: include, BypassCIDRs: legacyEntries(tun.Excludes, readFile, &record.Warnings)}
			match = &m
		default:
			record.Source = "routes"
			if len(tun.Excludes) != 0 {
				record.Warnings = append(record.Warnings, "excluded routes were installed as routes by earlier desktop versions and are kept as routes")
			}
			include := legacyEntries(append(slices.Clone(tun.Routes), tun.Excludes...), readFile, &record.Warnings)
			if len(include) != 0 {
				m := sysnet.RouteMatch{Mode: sysnet.ModeCustom, IncludeCIDRs: include}
				match = &m
			}
		}
		if match != nil {
			data := fmt.Sprintf("%s|%v|%v|%v|%v|%v", match.Mode, match.IncludeCIDRs, match.BypassCIDRs, match.GeoIPCountries, match.GeoIPInvert, in.ID)
			sum := sha256.Sum256([]byte(data))
			id := "legacy-tun-" + in.ID + "-" + hex.EncodeToString(sum[:4])
			record.RuleID = id
			if !ids[id] {
				ids[id] = true
				config.Routes = append(config.Routes, sysnet.RouteRule{ID: id, Name: in.Name + " (migrated)", Enabled: true, Priority: priority,
					Match: *match, Target: sysnet.RouteTarget{Type: sysnet.TargetTunInbound, InboundID: in.ID}})
				priority += 10
			}
		}
		if !slices.ContainsFunc(config.Migrations, func(m sysnet.Migration) bool {
			return m.InboundID == record.InboundID && m.RuleID == record.RuleID && m.Source == record.Source
		}) {
			config.Migrations = append(config.Migrations, record)
		}
		cleared = append(cleared, in.ID)
	}
	return config, cleared
}

// MigrateLegacyTun migrates and persists legacy TUN routing, returning the
// inbounds whose legacy settings the caller must clear. The configuration is
// saved first, so an interruption before clearing only repeats an idempotent
// migration.
func (m *Manager) MigrateLegacyTun(ctx context.Context, inbounds []contractinbound.Inbound, readFile func(string) ([]byte, error)) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store == nil {
		return nil, errors.New("the System Network configuration storage is unavailable")
	}
	next, cleared := MigrateLegacy(cloneConfig(m.config), inbounds, m.opts.Capabilities.Platform, readFile, time.Now())
	if len(cleared) == 0 {
		return nil, nil
	}
	if err := next.Validate(); err != nil {
		return nil, fmt.Errorf("migrated System Network configuration is invalid: %w", err)
	}
	if err := m.store.SaveSystemNetwork(ctx, next); err != nil {
		return nil, err
	}
	m.config, m.loaded = next, true
	log.Info("migrated TUN routing settings to System Network", "inbounds", cleared)
	m.reconcileLocked("legacy TUN routing migrated")
	return cleared, nil
}
