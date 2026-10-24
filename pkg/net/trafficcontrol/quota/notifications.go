package quota

import "time"

// NotifyOwned evaluates recovered counters and newly activated thresholds. It
// runs after publication, so validation drafts cannot emit operational alerts.
func (p *Plan) NotifyOwned() {
	now := time.Now().Unix()
	for i := range p.entries {
		e := &p.entries[i]
		if e.end != 0 && now >= e.end {
			continue
		}
		e.w.mu.Lock()
		if !e.w.retired.Load() {
			p.ledger.alert(e)
			p.ledger.notifyTermination(e)
		}
		e.w.mu.Unlock()
	}
}

func (l *Ledger) notifyTermination(e *entry) {
	if e.quota.Action != "terminate" || e.w.terminationNotified {
		return
	}
	for i, limit := range e.limit {
		if limit != 0 && e.w.used(i) >= limit {
			e.w.terminationNotified = true
			select {
			case l.terminations <- struct{}{}:
			default:
			}
			return
		}
	}
}
