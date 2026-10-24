package auth

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

// Report reads live counters; historical report sampling never decides quota
// admission. This control-path read also loads inactive owners' durable windows.
func (r *ResourcePolicies) Report(ctx context.Context, owner, credentialID string) (resource.Report, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if owner == "" || len(owner) > 128 || len(credentialID) > 128 {
		return resource.Report{}, ErrInvalid
	}
	user, err := r.store.User(ctx, owner)
	if err != nil {
		return resource.Report{}, err
	}
	config := r.Control.ResourceConfig()
	report := resource.Report{Revision: config.Revision, Enabled: config.Enabled, UserID: owner, Scopes: []resource.ScopeUsage{}, Quotas: []resource.QuotaUsage{}}
	groups := map[string]resource.GroupPolicy{}
	credentials := map[string]resource.Policy{}
	for _, g := range config.Groups {
		groups[g.GroupID] = g
	}
	for _, c := range config.Credentials {
		credentials[c.CredentialID] = c.Policy
	}
	policy := config.DefaultUser
	for _, override := range config.Users {
		if override.UserID == owner {
			policy = override.Policy
			break
		}
	}
	profile, limits := policy.Profile, policy.Limits
	rows, err := r.store.db.QueryContext(ctx, `SELECT g.id,g.name FROM traffic_group_members m JOIN traffic_groups g ON g.id=m.group_id WHERE m.user_id=? AND g.deleted=0 ORDER BY g.id`, owner)
	if err != nil {
		return report, err
	}
	type memberGroup struct{ id, name string }
	var memberships []memberGroup
	for rows.Next() {
		var group memberGroup
		if err := rows.Scan(&group.id, &group.name); err != nil {
			_ = rows.Close()
			return report, err
		}
		memberships = append(memberships, group)
		profile = resource.IntersectProfile(profile, groups[group.id].IndividualProfile)
		limits = resource.IntersectLimits(limits, groups[group.id].UserLimits)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return report, err
	}
	add := func(scope, id, name string, profile resource.Profile, limits resource.Limits, quotas []resource.Quota, live trafficcontrol.IdentityResources) error {
		view := resource.ScopeUsage{LastRejection: live.LastRejection, LastRejectedAt: live.LastRejectedAt, Scope: scope, ScopeID: id, Name: name, ConfiguredProfile: profile, ConfiguredLimits: limits, RejectedSessions: strconv.FormatUint(live.TCP.DeniedSessions+live.UDP.DeniedSessions, 10), RejectedPackets: strconv.FormatUint(live.Total.DeniedPackets, 10), Sessions: resource.Sessions{TCP: live.TCP.Sessions, UDP: live.UDP.Sessions, Total: live.Total.Sessions}}
		if config.Enabled {
			view.EnforcedProfile = profile
			view.EnforcedLimits = limits
		}
		if len(quotas) > 0 {
			bindings := make([]quota.Binding, 0, len(quotas))
			for _, q := range quotas {
				bindings = append(bindings, quota.Binding{Scope: scope, ScopeID: id, OwnerUserID: owner, Quota: q})
			}
			plan, err := r.Ledger.Prepare(ctx, bindings, time.Now())
			if err != nil {
				return err
			}
			report.Quotas = append(report.Quotas, plan.Usage()...)
			if config.Enabled {
				effect, err := plan.Effects(time.Now())
				if err != nil && !errors.Is(err, quota.ErrExpired) {
					return err
				}
				if err == nil {
					view.EnforcedProfile = resource.IntersectProfile(view.EnforcedProfile, effect.ReducedSpeed)
				}
			}
		}
		report.Scopes = append(report.Scopes, view)
		return nil
	}
	base := r.Control.Config()
	if base.Enabled {
		report.Scopes = append(report.Scopes, resource.ScopeUsage{Scope: "global", ScopeID: "global", ConfiguredProfile: base.Global, EnforcedProfile: base.Global, RejectedSessions: "0", RejectedPackets: "0"})
	}
	userStatus, _ := r.Control.UserResourceStatus(owner)
	if err := add("user", owner, user.Login, profile, limits, policy.Quotas, userStatus); err != nil {
		return report, err
	}
	for _, group := range memberships {
		configured, exists := groups[group.id]
		if !exists {
			continue
		}
		if err := add("group", group.id, group.name, configured.SharedProfile, resource.Limits{}, configured.Quotas, trafficcontrol.IdentityResources{}); err != nil {
			return report, err
		}
	}
	// Metadata-only credential reads preserve the provider lock ordering:
	// Report never acquires ProxyCredentials.mu while holding this service mutex.
	items, err := r.proxy.List(ctx, owner)
	if err != nil {
		return report, err
	}
	matched := credentialID == ""
	for _, item := range items {
		if credentialID != "" && item.ID != credentialID {
			continue
		}
		matched = true
		_, live, _ := r.Control.IdentityResourceStatus(owner, item.ID)
		p := credentials[item.ID]
		if err := add("credential", item.ID, item.Name, p.Profile, p.Limits, p.Quotas, live); err != nil {
			return report, err
		}
	}
	if !matched {
		return resource.Report{}, ErrInvalid
	}
	diagnostics := r.Ledger.Diagnostics()
	report.PersistenceDegraded = diagnostics.PersistenceFailures > 0 || diagnostics.DroppedEvents > 0 || r.alertFailures.Load() > 0
	return report, nil
}
