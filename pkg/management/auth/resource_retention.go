package auth

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

// Resource policy publication owns mu while the metadata and definition sets
// are captured. Disabled policies keep their budgets; deleted owners and removed
// definitions retire in-memory state without resetting durable usage.
func (r *ResourcePolicies) retireQuotaState(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	owners := func(query string) (map[string]bool, error) {
		rows, err := r.store.db.QueryContext(ctx, query)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		result := map[string]bool{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			result[id] = true
		}
		return result, rows.Err()
	}
	users, err := owners(`SELECT id FROM management_users`)
	if err != nil {
		return err
	}
	credentials, err := owners(`SELECT id FROM proxy_credentials`)
	if err != nil {
		return err
	}
	c := r.Control.ResourceConfig()
	userQuotas, credentialQuotas, groupQuotas := map[string][]resource.Quota{}, map[string][]resource.Quota{}, map[string][]resource.Quota{}
	for _, u := range c.Users {
		userQuotas[u.UserID] = u.Policy.Quotas
	}
	for _, d := range c.Credentials {
		credentialQuotas[d.CredentialID] = d.Policy.Quotas
	}
	for _, g := range c.Groups {
		groupQuotas[g.GroupID] = g.Quotas
	}
	r.Ledger.RetireUnused(func(key quota.Key) bool {
		var definitions []resource.Quota
		switch key.Scope {
		case "user":
			if !users[key.ScopeID] {
				return false
			}
			var explicit bool
			definitions, explicit = userQuotas[key.ScopeID]
			if !explicit {
				definitions = c.DefaultUser.Quotas
			}
		case "credential":
			if !credentials[key.ScopeID] {
				return false
			}
			definitions = credentialQuotas[key.ScopeID]
		case "group":
			definitions = groupQuotas[key.ScopeID]
		}
		for _, definition := range definitions {
			if definition.ID == key.QuotaID && definition.Period == key.Period {
				return true
			}
		}
		return false
	})
	return nil
}
