package quota

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
)

func (p *Plan) ExpiresAt() int64 { return p.until }

func (p *Plan) Admit(now time.Time) error {
	effects, err := p.Effects(now)
	if err != nil {
		return err
	}
	if effects.BlockNew {
		p.ledger.denied.Add(1)
		p.lock()
		for i := range p.len() {
			e := p.at(i)
			if e.quota.Action != "block_new" && e.quota.Action != "terminate" {
				continue
			}
			for i, limit := range e.limit {
				if limit != 0 && add(e.w.used(i), e.w.inflight[i]) >= limit {
					e.w.record.Denied = add(e.w.record.Denied, 1)
					e.w.version++
					break
				}
			}
		}
		p.unlock()
		return ErrExhausted
	}
	return nil
}

// Effects describes exhausted quotas. Forwarding composes ReducedSpeed with
// its existing shaper, and terminates sessions only for the Terminate action.
type Effects struct {
	BlockNew, Terminate bool
	ReducedSpeed        resource.Profile
}

func (p *Plan) Effects(now time.Time) (Effects, error) {
	if p.ledger.closed.Load() {
		return Effects{}, ErrClosed
	}
	if p.until != 0 && now.Unix() >= p.until {
		return Effects{}, ErrExpired
	}
	p.lock()
	defer p.unlock()
	var result Effects
	for i := range p.len() {
		e := p.at(i)
		if e.w.retired.Load() {
			return Effects{}, ErrRetired
		}
		exceeded := false
		for i, limit := range e.limit {
			exceeded = exceeded || limit != 0 && add(e.w.used(i), e.w.inflight[i]) >= limit
		}
		if !exceeded {
			continue
		}
		switch e.quota.Action {
		case "block_new":
			result.BlockNew = true
		case "terminate":
			result.BlockNew, result.Terminate = true, true
		case "throttle":
			result.ReducedSpeed = resource.IntersectProfile(result.ReducedSpeed, e.quota.ReducedSpeed)
		}
	}
	return result, nil
}
