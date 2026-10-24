package quota

import "github.com/Asutorufa/yuhaiin/pkg/contract/resource"

// Throttle retains immutable limits and a shared window. Monotonic published
// counters select reduced speeds without a quota lock on every packet. Hard
// byte reservations still use authoritative window locks.
type Throttle struct {
	w       *window
	limit   Amounts
	profile resource.Profile
}

func (t *Throttle) Key() Key                  { return t.w.record.Key }
func (t *Throttle) Profile() resource.Profile { return t.profile }
func (t *Throttle) Exceeded() bool {
	for i, limit := range t.limit {
		if limit != 0 && t.w.published[i].Load() >= limit {
			return true
		}
	}
	return false
}

// OwnThrottles compiles only this segment; shared user/group guards are reused.
// It is called on the control path, never while forwarding.
func (p *Plan) OwnThrottles() []*Throttle {
	var result []*Throttle
	for _, e := range p.entries {
		if e.quota.Action == "throttle" {
			result = append(result, &Throttle{w: e.w, limit: e.limit, profile: e.quota.ReducedSpeed})
		}
	}
	return result
}
