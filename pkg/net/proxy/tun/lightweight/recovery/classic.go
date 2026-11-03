package recovery

import "time"

// classic preserves the stack's DupACK/SACK and partial NewReno ACK rules.
// It does not claim exhaustive RFC 6675 conformance.
type classic struct{}

func (*classic) Sent(SentEvent)               {}
func (*classic) Delivered(Segment, time.Time) {}
func (*classic) Evaluate(e Event, flight Flight) Decision {
	var d Decision
	if e.Kind == Timer || e.Kind == Transmit {
		return d
	}
	n := flight.Len()
	if e.Kind == Timeout || e.Kind == Reneging {
		for i := range n {
			s := flight.At(i)
			if !s.SACKed && !s.Lost {
				d.lose(s)
			}
		}
		return d
	}
	if e.HasSACK {
		var above uint64
		for i := n - 1; i >= 0; i-- {
			s := flight.At(i)
			if s.SACKed {
				above += uint64(s.End - s.Start)
				continue
			}
			if s.Repair || s.Lost {
				continue
			}
			evidence := above
			if s.Transmissions > 1 {
				evidence = 0
				for j := i + 1; j < n; j++ {
					later := flight.At(j)
					if later.SACKed && !before(later.Start, s.RetransmitEnd) {
						evidence += uint64(later.End - later.Start)
					}
					if evidence >= 3*uint64(e.MSS) {
						break
					}
				}
			}
			if evidence >= 3*uint64(e.MSS) {
				d.lose(s)
			}
		}
	}
	if d.Count == 0 && (e.DupACKs == 3 && !e.InRecovery || e.Acked > 0 && e.InRecovery && !e.RecoveryDone) {
		for i := range n {
			s := flight.At(i)
			if s.SACKed {
				continue
			}
			if s.Transmissions == 1 && !s.Repair && !s.Lost {
				d.lose(s)
			}
			break
		}
	}
	return d
}
