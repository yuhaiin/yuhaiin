package trafficcontrol

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol/quota"
)

type limiterScope struct {
	limiter *Limiter
	when    *quota.Throttle
}

// Keep the existing three scopes inline. Identity scopes are shared immutable
// slices, compiled once per credential rather than copied per connection.
type scopeSet struct {
	base        [3]*Limiter
	extra       []limiterScope
	device      []limiterScope
	blocked     bool
	conditional [5]uint64
}

func (s *scopeSet) len() int { return len(s.base) + len(s.extra) + len(s.device) }
func (s *scopeSet) at(i int) limiterScope {
	if i < len(s.base) {
		return limiterScope{limiter: s.base[i]}
	}
	i -= len(s.base)
	var selected limiterScope
	if i < len(s.extra) {
		selected = s.extra[i]
	} else {
		selected = s.device[i-len(s.extra)]
	}
	if selected.when != nil && s.conditional[i/64]&(1<<uint(i%64)) == 0 {
		return limiterScope{}
	}
	return selected
}

func (s *scopeSet) selectConditional() {
	for i, selected := range s.extra {
		if selected.when != nil && selected.when.Exceeded() {
			s.conditional[i/64] |= 1 << uint(i%64)
		}
	}
	for i, selected := range s.device {
		index := len(s.extra) + i
		if selected.when != nil && selected.when.Exceeded() {
			s.conditional[index/64] |= 1 << uint(index%64)
		}
	}
}

func pairScope(pair compiledPair, d Direction) limiterScope {
	l, spec := pair.up, pair.spec.Upload
	if d == Download {
		l, spec = pair.down, pair.spec.Download
	}
	if spec.BytesPerSecond == 0 {
		return limiterScope{}
	}
	return limiterScope{limiter: l}
}

func lockScopes(s scopeSet) {
	for i := range s.len() {
		if l := s.at(i).limiter; l != nil {
			l.mu.Lock()
		}
	}
}
func unlockScopes(s scopeSet) {
	for i := s.len() - 1; i >= 0; i-- {
		if l := s.at(i).limiter; l != nil {
			l.mu.Unlock()
		}
	}
}

func scopesCurrent(s scopeSet, generation uint64) bool {
	for i := range s.len() {
		if l := s.at(i).limiter; l != nil && l.generation > generation {
			return false
		}
	}
	return true
}

// Stage changed rates under their own bucket locks. Operations using an older
// snapshot retry those buckets until publication, while unrelated scopes keep
// forwarding. This retains rate history even across updates with no intervening
// traffic; a lazy reconcile could otherwise mint credits at an obsolete rate.
func (m *Manager) stageSnapshot(s *policySnapshot, generation uint64) {
	now := time.Now()
	stage := func(p compiledPair) {
		for _, d := range [2]Direction{Upload, Download} {
			l, spec := p.up, p.spec.Upload
			if d == Download {
				l, spec = p.down, p.spec.Download
			}
			if l == nil {
				continue
			}
			if spec.BytesPerSecond > 0 && spec.BurstBytes == 0 {
				spec.BurstBytes = 64 << 10
			}
			l.mu.Lock()
			if l.rate != spec.BytesPerSecond || l.burst != spec.BurstBytes {
				configureLimiter(l, spec.BytesPerSecond, spec.BurstBytes, now)
				l.generation = generation
			}
			l.mu.Unlock()
		}
	}
	stage(s.global)
	stage(s.fallback)
	for _, p := range s.inbound {
		stage(p)
	}
	for _, p := range s.route {
		stage(p)
	}
	if r := s.resources; r != nil {
		stageResourceGovernors(r, generation)
		for _, p := range r.groups {
			stage(p)
		}
		for _, p := range r.users {
			stage(p)
		}
		for _, p := range r.credentials {
			stage(p)
		}
		for _, p := range r.throttles {
			stage(p)
		}
	}
	s.generation = generation
}
