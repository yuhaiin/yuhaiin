package trafficcontrol

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

var ErrUnknownResourceIdentity = errors.New("trafficcontrol: identity absent from resource snapshot")

type identityKey struct{ userID, credentialID string }

// IdentityBinding is supplied by the optional identity module on the control
// path. It contains stable authenticated IDs and no credential proofs.
type IdentityBinding struct {
	UserID, CredentialID string
	GroupIDs             []string
}

type identityScopes struct {
	up, down             []limiterScope
	deviceUp, deviceDown []limiterScope
	pps                  bool
}

type resourceSnapshot struct {
	config                             resource.Config
	groups, users, credentials         map[string]compiledPair
	identities                         map[identityKey]identityScopes
	quotaPlans                         map[identityKey]*quota.Plan
	sharedQuotaPlans                   map[string]*quota.Plan
	bindings                           []IdentityBinding
	nextReset                          int64
	throttles                          map[quota.Key]compiledPair
	userGovernors, credentialGovernors map[string]*IdentityGovernor
	userLimits                         map[string]resource.Limits
	hasTermination                     bool
}

type PreparedResources struct {
	owner          *Manager
	expected, next *resourceSnapshot
}

var ErrResourceConflict = errors.New("trafficcontrol: resource snapshot changed")

// ApplyResources publishes group/user/device shaping into the existing manager.
// Old Policy handles resolve this snapshot on their next operation. Preparing
// bindings performs no membership lookup or SQL on a forwarding path.
func (m *Manager) ApplyResources(config resource.Config, bindings []IdentityBinding) error {
	prepared, err := m.PrepareResources(context.Background(), config, bindings)
	if err != nil {
		return err
	}
	return m.ActivateResources(prepared)
}

// PrepareResources performs every fallible validation and quota-state load
// before a management transaction commits. Activation performs no persistence.
func (m *Manager) PrepareResources(ctx context.Context, config resource.Config, bindings []IdentityBinding) (*PreparedResources, error) {
	if err := resource.ValidateConfig(config); err != nil {
		return nil, err
	}
	if len(bindings) > 65536 {
		return nil, errors.New("trafficcontrol: too many resource identities")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.active.Load()
	var previous *resourceSnapshot
	if old != nil {
		previous = old.resources
	}
	r, err := compileResources(config, bindings, previous)
	if err != nil {
		return nil, err
	}
	if err := m.prepareQuotaPlans(ctx, r, previous); err != nil {
		return nil, err
	}
	if err := prepareResourceGovernors(r, previous); err != nil {
		return nil, err
	}
	return &PreparedResources{owner: m, expected: previous, next: r}, nil
}

func (m *Manager) ActivateResources(prepared *PreparedResources) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.active.Load()
	if prepared == nil || prepared.owner != m || old.resources != prepared.expected {
		return ErrResourceConflict
	}
	next := *old
	next.resources = prepared.next
	next.changed = make(chan struct{})
	m.stageSnapshot(&next, old.generation+1)
	m.active.Store(&next)
	close(old.changed)
	for _, plan := range next.resources.sharedQuotaPlans {
		if plan != nil {
			plan.NotifyOwned()
		}
	}
	for key, plan := range next.resources.quotaPlans {
		if plan != next.resources.sharedQuotaPlans[key.userID] {
			plan.NotifyOwned()
		}
	}
	return nil
}

func compileResources(config resource.Config, bindings []IdentityBinding, old *resourceSnapshot) (*resourceSnapshot, error) {
	r := &resourceSnapshot{config: resource.CloneConfig(config), bindings: cloneIdentityBindings(bindings), groups: map[string]compiledPair{}, users: map[string]compiledPair{}, credentials: map[string]compiledPair{}, identities: map[identityKey]identityScopes{}}
	r.userLimits = make(map[string]resource.Limits)
	groups := make(map[string]resource.GroupPolicy, len(config.Groups))
	users := make(map[string]resource.Policy, len(config.Users))
	credentials := make(map[string]resource.Policy, len(config.Credentials))
	for _, g := range config.Groups {
		groups[g.GroupID] = g
	}
	for _, u := range config.Users {
		users[u.UserID] = u.Policy
	}
	for _, c := range config.Credentials {
		credentials[c.CredentialID] = c.Policy
	}
	pair := func(profile Profile, prior map[string]compiledPair, id string) (compiledPair, error) {
		next, err := compilePair(profile)
		if err != nil {
			return next, err
		}
		return retainPair(prior[id], next, time.Time{}), nil
	}
	priorGroups, priorUsers, priorCredentials := map[string]compiledPair{}, map[string]compiledPair{}, map[string]compiledPair{}
	if old != nil {
		priorGroups, priorUsers, priorCredentials = old.groups, old.users, old.credentials
	}
	for _, g := range config.Groups {
		p, err := pair(g.SharedProfile, priorGroups, g.GroupID)
		if err != nil {
			return nil, err
		}
		r.groups[g.GroupID] = p
	}
	memberGroups := map[string][]string{}
	userScopes := map[string]identityScopes{}
	credentialOwners := map[string]string{}
	for _, b := range r.bindings {
		if b.UserID == "" || b.CredentialID == "" || len(b.UserID) > 128 || len(b.CredentialID) > 128 || len(b.GroupIDs) > 64 {
			return nil, errors.New("trafficcontrol: invalid resource identity")
		}
		key := identityKey{b.UserID, b.CredentialID}
		if _, exists := r.identities[key]; exists {
			return nil, errors.New("trafficcontrol: duplicate resource identity")
		}
		if owner := credentialOwners[b.CredentialID]; owner != "" && owner != b.UserID {
			return nil, errors.New("trafficcontrol: conflicting credential owner")
		}
		credentialOwners[b.CredentialID] = b.UserID
		ids := b.GroupIDs
		for i, id := range ids {
			if id == "" || len(id) > 128 || i > 0 && ids[i-1] == id {
				return nil, errors.New("trafficcontrol: invalid resource membership")
			}
		}
		if prior, exists := memberGroups[b.UserID]; exists && !slices.Equal(prior, ids) {
			return nil, errors.New("trafficcontrol: conflicting user memberships")
		}
		memberGroups[b.UserID] = ids
		user, exists := r.users[b.UserID]
		if !exists {
			policy, override := users[b.UserID]
			if !override {
				policy = config.DefaultUser
			}
			profile := policy.Profile
			limits := policy.Limits
			for _, id := range ids {
				profile = resource.IntersectProfile(profile, groups[id].IndividualProfile)
				limits = resource.IntersectLimits(limits, groups[id].UserLimits)
			}
			var err error
			user, err = pair(profile, priorUsers, b.UserID)
			if err != nil {
				return nil, err
			}
			r.users[b.UserID] = user
			r.userLimits[b.UserID] = limits
		}
		credential, exists := r.credentials[b.CredentialID]
		if !exists {
			var err error
			credential, err = pair(credentials[b.CredentialID].Profile, priorCredentials, b.CredentialID)
			if err != nil {
				return nil, err
			}
			r.credentials[b.CredentialID] = credential
		}
		selected, exists := userScopes[b.UserID]
		if !exists {
			for _, id := range ids {
				if scope := pairScope(r.groups[id], Upload); scope.limiter != nil {
					selected.up = append(selected.up, scope)
				}
				if scope := pairScope(r.groups[id], Download); scope.limiter != nil {
					selected.down = append(selected.down, scope)
				}
			}
			if scope := pairScope(user, Upload); scope.limiter != nil {
				selected.up = append(selected.up, scope)
			}
			if scope := pairScope(user, Download); scope.limiter != nil {
				selected.down = append(selected.down, scope)
			}
			userScopes[b.UserID] = selected
		}
		if scope := pairScope(credential, Upload); scope.limiter != nil {
			selected.deviceUp = []limiterScope{scope}
		}
		if scope := pairScope(credential, Download); scope.limiter != nil {
			selected.deviceDown = []limiterScope{scope}
		}
		selected.pps = r.userLimits[b.UserID].PacketsPerSecond > 0 || credentials[b.CredentialID].Limits.PacketsPerSecond > 0

		r.identities[key] = selected
	}
	return r, nil
}

func (s *policySnapshot) scopeSet(inboundID, routeID string, key identityKey, d Direction, identified bool) scopeSet {
	result := scopeSet{}
	if s.config.Enabled {
		inbound, hasInbound := s.inbound[inboundID]
		rule, hasRule := s.route[routeID]
		fallback := s.fallback
		if hasInbound || hasRule {
			fallback = inbound
		}
		for i, p := range [3]compiledPair{s.global, fallback, rule} {
			result.base[i] = pairScope(p, d).limiter
		}
	}
	if s.resources == nil || !s.resources.config.Enabled || !identified {
		return result
	}
	identity, ok := s.resources.identities[key]
	if !ok {
		result.blocked = true
		return result
	}
	result.extra, result.device = identity.up, identity.deviceUp
	if d == Download {
		result.extra, result.device = identity.down, identity.deviceDown
	}
	result.selectConditional()
	return result
}

// ResolveIdentity is a control-path convenience. Forwarding reuses the shared
// authentication identity through ResolveAuthenticated without allocating IDs.
func (m *Manager) ResolveIdentity(inboundID, routeID, userID, credentialID string) Policy {
	if userID == "" && credentialID == "" {
		return m.Resolve(inboundID, routeID)
	}
	return m.ResolveAuthenticated(inboundID, routeID, &proxyauth.Identity{UserID: userID, CredentialID: credentialID})
}

func (m *Manager) ResolveAuthenticated(inboundID, routeID string, identity *proxyauth.Identity) Policy {
	p := m.Resolve(inboundID, routeID)
	p.identity = identity
	return p
}

func (p *Policy) identityKey() identityKey {
	if p.identity == nil {
		return identityKey{}
	}
	return identityKey{p.identity.UserID, p.identity.CredentialID}
}

func (p *Policy) unmanaged(s *policySnapshot) bool {
	return !s.config.Enabled && (p.identity == nil || s.resources == nil || !s.resources.config.Enabled)
}

func (m *Manager) ResourceConfig() resource.Config {
	s := m.active.Load()
	if s.resources == nil {
		return resource.Config{}
	}
	return resource.CloneConfig(s.resources.config)
}

func (m *Manager) ValidateResources(config resource.Config, bindings []IdentityBinding) error {
	if err := resource.ValidateConfig(config); err != nil {
		return err
	}
	if len(bindings) > 65536 {
		return fmt.Errorf("trafficcontrol: too many resource identities")
	}
	_, err := compileResources(config, bindings, nil)
	return err
}
