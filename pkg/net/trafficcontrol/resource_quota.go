package trafficcontrol

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

func (m *Manager) prepareQuotaPlans(ctx context.Context, r, previous *resourceSnapshot) error {
	if !r.config.Enabled {
		return nil
	}
	r.quotaPlans = make(map[identityKey]*quota.Plan)
	r.throttles = make(map[quota.Key]compiledPair)
	groups := map[string][]resource.Quota{}
	users, credentials := map[string][]resource.Quota{}, map[string][]resource.Quota{}
	for _, g := range r.config.Groups {
		groups[g.GroupID] = g.Quotas
	}
	for _, u := range r.config.Users {
		users[u.UserID] = u.Policy.Quotas
	}
	for _, c := range r.config.Credentials {
		credentials[c.CredentialID] = c.Policy.Quotas
	}
	basePlans := map[string]*quota.Plan{}
	r.sharedQuotaPlans = basePlans
	baseScopes := map[string]identityScopes{}
	now := time.Now()
	appendThrottles := func(selected *identityScopes, plan *quota.Plan, device bool) error {
		for _, guard := range plan.OwnThrottles() {
			key := guard.Key()
			pair, exists := r.throttles[key]
			if !exists {
				var err error
				pair, err = compilePair(guard.Profile())
				if err != nil {
					return err
				}
				if previous != nil {
					pair = retainPair(previous.throttles[key], pair, time.Time{})
				}
				r.throttles[key] = pair
			}
			if scope := pairScope(pair, Upload); scope.limiter != nil {
				scope.when = guard
				if device {
					selected.deviceUp = append(selected.deviceUp, scope)
				} else {
					selected.up = append(selected.up, scope)
				}
			}
			if scope := pairScope(pair, Download); scope.limiter != nil {
				scope.when = guard
				if device {
					selected.deviceDown = append(selected.deviceDown, scope)
				} else {
					selected.down = append(selected.down, scope)
				}
			}
		}
		return nil
	}
	for _, identity := range r.bindings {
		key := identityKey{identity.UserID, identity.CredentialID}
		selected := r.identities[key]
		base, exists := basePlans[identity.UserID]
		if !exists {
			var bindings []quota.Binding
			appendQuotas := func(scope, id string, quotas []resource.Quota) {
				for _, q := range quotas {
					if q.Action == "terminate" {
						r.hasTermination = true
					}
					bindings = append(bindings, quota.Binding{Scope: scope, ScopeID: id, OwnerUserID: identity.UserID, Quota: q})
				}
			}
			user, override := users[identity.UserID]
			if !override {
				user = r.config.DefaultUser.Quotas
			}
			appendQuotas("user", identity.UserID, user)
			for _, id := range identity.GroupIDs {
				appendQuotas("group", id, groups[id])
			}
			if len(bindings) > 0 {
				if m.quotas == nil {
					return errors.New("trafficcontrol: quota policies require a durable ledger")
				}
				var err error
				base, err = m.quotas.Prepare(ctx, bindings, now)
				if err != nil {
					return err
				}
				if err := appendThrottles(&selected, base, false); err != nil {
					return err
				}
			}
			basePlans[identity.UserID] = base
			baseScopes[identity.UserID] = identityScopes{up: selected.up, down: selected.down}
		} else {
			selected.up, selected.down = baseScopes[identity.UserID].up, baseScopes[identity.UserID].down
		}
		plan := base
		if device := credentials[identity.CredentialID]; len(device) > 0 {
			if m.quotas == nil {
				return errors.New("trafficcontrol: quota policies require a durable ledger")
			}
			bindings := make([]quota.Binding, 0, len(device))
			for _, q := range device {
				if q.Action == "terminate" {
					r.hasTermination = true
				}
				bindings = append(bindings, quota.Binding{Scope: "credential", ScopeID: identity.CredentialID, OwnerUserID: identity.UserID, Quota: q})
			}
			var err error
			plan, err = m.quotas.PrepareCredential(ctx, base, bindings, now)
			if err != nil {
				return err
			}
			if err := appendThrottles(&selected, plan, true); err != nil {
				return err
			}
		}
		r.identities[key] = selected
		if plan != nil {
			r.quotaPlans[key] = plan
			if end := plan.ExpiresAt(); end != 0 && (r.nextReset == 0 || end < r.nextReset) {
				r.nextReset = end
			}
		}
	}
	return nil
}

func cloneIdentityBindings(bindings []IdentityBinding) []IdentityBinding {
	result := slices.Clone(bindings)
	groups := map[string][]string{}
	for i := range result {
		previous, exists := groups[result[i].UserID]
		if exists && slices.Equal(previous, result[i].GroupIDs) {
			result[i].GroupIDs = previous
			continue
		}
		ids := slices.Clone(result[i].GroupIDs)
		slices.Sort(ids)
		if exists && slices.Equal(previous, ids) {
			ids = previous
		}
		result[i].GroupIDs = ids
		if !exists {
			groups[result[i].UserID] = ids
		}
	}
	return result
}

// RefreshQuotaWindows is called by the optional module's background scheduler.
// An expired plan fails closed until a successful new UTC-window publication.
func (m *Manager) RefreshQuotaWindows(ctx context.Context) error {
	r := m.active.Load().resources
	if r == nil || r.nextReset == 0 || time.Now().Unix() < r.nextReset {
		return nil
	}
	prepared, err := m.PrepareResources(ctx, r.config, r.bindings)
	if err != nil {
		return err
	}
	return m.ActivateResources(prepared)
}

// QuotaPlan resolves the current shared live counters without a DB query.
func (p Policy) QuotaPlan() (*quota.Plan, error) {
	plan, _, err := p.quotaState()
	return plan, err
}

func (p Policy) quotaState() (*quota.Plan, <-chan struct{}, error) {
	if p.manager == nil || p.identity == nil {
		return nil, nil, nil
	}
	s := p.manager.active.Load()
	r := s.resources
	if r == nil || !r.config.Enabled {
		return nil, s.changed, nil
	}
	if _, ok := r.identities[p.identityKey()]; !ok {
		return nil, s.changed, ErrUnknownResourceIdentity
	}
	return r.quotaPlans[p.identityKey()], s.changed, nil
}
