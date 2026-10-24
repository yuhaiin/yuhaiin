package trafficcontrol

import (
	"errors"
	"maps"
	"runtime"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

func prepareResourceGovernors(next, old *resourceSnapshot) error {
	next.userGovernors = make(map[string]*IdentityGovernor)
	next.credentialGovernors = make(map[string]*IdentityGovernor)
	if old != nil {
		maps.Copy(next.userGovernors, old.userGovernors)
		maps.Copy(next.credentialGovernors, old.credentialGovernors)
		// A scope absent from both old and next selections cannot admit new
		// traffic. Reclaim only after its leases and rate debt have drained.
		now := time.Now()
		for id, g := range next.userGovernors {
			_, current := old.userLimits[id]
			_, future := next.userLimits[id]
			if !current && !future && g.reclaimable(now) {
				delete(next.userGovernors, id)
			}
		}
		for id, g := range next.credentialGovernors {
			_, current := old.credentials[id]
			_, future := next.credentials[id]
			if !current && !future && g.reclaimable(now) {
				delete(next.credentialGovernors, id)
			}
		}
	}
	for id, limits := range next.userLimits {
		if next.userGovernors[id] == nil {
			if len(next.userGovernors) >= 65536 {
				return errors.New("trafficcontrol: user resource capacity reached")
			}
			if !next.config.Enabled {
				limits = resource.Limits{}
			}
			g, err := NewIdentityGovernor(limits)
			if err != nil {
				return err
			}
			next.userGovernors[id] = g
		}
	}
	credentialLimits := map[string]resource.Limits{}
	for _, binding := range next.config.Credentials {
		credentialLimits[binding.CredentialID] = binding.Policy.Limits
	}
	for id := range next.credentials {
		if next.credentialGovernors[id] == nil {
			if len(next.credentialGovernors) >= 65536 {
				return errors.New("trafficcontrol: credential resource capacity reached")
			}
			limits := credentialLimits[id]
			if !next.config.Enabled {
				limits = resource.Limits{}
			}
			g, err := NewIdentityGovernor(limits)
			if err != nil {
				return err
			}
			next.credentialGovernors[id] = g
		}
	}
	return nil
}

func (p Policy) admitIdentityPacket() bool {
	if p.manager == nil || p.identity == nil {
		return true
	}
	r := p.manager.active.Load().resources
	if r == nil || !r.config.Enabled {
		return true
	}
	identity, ok := r.identities[p.identityKey()]
	if !ok {
		return false
	}
	if !identity.pps {
		return true
	}
	now := time.Now()
	return r.credentialGovernors[p.identity.CredentialID].AdmitPacket(now) && r.userGovernors[p.identity.UserID].AdmitPacket(now)
}

func stageResourceGovernors(r *resourceSnapshot, generation uint64) {
	stage := func(g *IdentityGovernor, limits resource.Limits) {
		if !r.config.Enabled {
			limits = resource.Limits{}
		}
		if g.Snapshot().Limits == limits {
			return
		}
		g.generation.Store(generation)
		_ = g.UpdateLimits(limits) // Validated completely during preparation.
	}
	for id, limits := range r.userLimits {
		stage(r.userGovernors[id], limits)
	}
	credentials := map[string]resource.Limits{}
	for _, binding := range r.config.Credentials {
		credentials[binding.CredentialID] = binding.Policy.Limits
	}
	for id := range r.credentials {
		stage(r.credentialGovernors[id], credentials[id])
	}
}

type ResourceSession struct {
	user, credential *Session
	once             sync.Once
}

func (r *ResourceSession) Release() {
	if r == nil {
		return
	}
	r.once.Do(func() { r.user.Release(); r.credential.Release() })
}

// AcquireResourceSession runs before global/inbound admission, keeping a noisy
// user's failed attempts out of unrelated users' shared creation budgets.
func (m *Manager) AcquireResourceSession(userID, credentialID string, udp bool) (*ResourceSession, bool) {
	if userID == "" && credentialID == "" {
		return nil, true
	}
	key := identityKey{userID, credentialID}
	for {
		s := m.active.Load()
		r := s.resources
		if r == nil {
			return nil, true
		}
		if _, ok := r.identities[key]; !ok {
			return nil, !r.config.Enabled
		}
		if plan := r.quotaPlans[key]; plan != nil {
			if err := plan.Admit(time.Now()); err != nil {
				reason := rejectQuotaCredit
				if errors.Is(err, quota.ErrExhausted) {
					reason = rejectQuota
				}
				r.userGovernors[userID].recordRejection(reason, time.Now())
				return nil, false
			}
		}
		user, credential := r.userGovernors[userID], r.credentialGovernors[credentialID]
		if user.generation.Load() > s.generation || credential.generation.Load() > s.generation {
			runtime.Gosched()
			continue
		}
		acquire := func(g *IdentityGovernor) (*Session, bool) {
			if udp {
				return g.AcquireUDP()
			}
			return g.AcquireTCP()
		}
		device, ok := acquire(credential)
		if !ok {
			return nil, false
		}
		owner, ok := acquire(user)
		if !ok {
			device.Release()
			return nil, false
		}
		if m.active.Load() != s || user.generation.Load() > s.generation || credential.generation.Load() > s.generation {
			owner.Release()
			device.Release()
			runtime.Gosched()
			continue
		}
		return &ResourceSession{user: owner, credential: device}, true
	}
}

func (m *Manager) HasQuotaTermination() bool {
	r := m.active.Load().resources
	return r != nil && r.config.Enabled && r.hasTermination
}

func (m *Manager) IdentityResourceStatus(userID, credentialID string) (IdentityResources, IdentityResources, bool) {
	r := m.active.Load().resources
	if r == nil {
		return IdentityResources{}, IdentityResources{}, false
	}
	user, credential := r.userGovernors[userID], r.credentialGovernors[credentialID]
	if user == nil || credential == nil {
		return IdentityResources{}, IdentityResources{}, false
	}
	return user.Snapshot(), credential.Snapshot(), true
}

func (m *Manager) UserResourceStatus(userID string) (IdentityResources, bool) {
	r := m.active.Load().resources
	if r == nil || r.userGovernors[userID] == nil {
		return IdentityResources{}, false
	}
	return r.userGovernors[userID].Snapshot(), true
}
