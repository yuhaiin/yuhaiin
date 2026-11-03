package recovery

import (
	"time"
)

// rack implements RFC 8985 time-based detection and tail loss probing. Local
// monotonic transmission times suffice; TCP Timestamp negotiation is optional.
type rack struct {
	latest, lastSent, minStamp                        time.Time
	latestEnd, forward                                uint32
	rtt, minRTT                                       time.Duration
	reordered, forwardSet                             bool
	multiplier, persist                               int
	dsackRound                                        uint32
	dsackRoundSet                                     bool
	probeEnd, probeBytes                              uint32
	probePending, probeRetrans, probed, rttSinceProbe bool
	pto                                               time.Time
}

func (r *rack) Sent(e SentEvent) {
	if !e.Data {
		return
	}
	r.lastSent = e.Sent
	if e.Probe {
		r.probeEnd, r.probePending = e.Next, true
		r.probeBytes = e.End - e.Start
		r.probeRetrans = e.Transmissions > 1
		r.probed, r.rttSinceProbe = true, false
		r.pto = time.Time{}
	} else if e.Transmissions == 1 {
		r.pto = time.Time{}
	}
}

func (r *rack) Delivered(s Segment, now time.Time) {
	if !s.Data {
		return
	}
	rtt := now.Sub(s.Sent)
	if rtt <= 0 {
		return
	}
	if s.Transmissions == 1 {
		if r.minRTT == 0 || rtt < r.minRTT || now.Sub(r.minStamp) > 10*time.Second {
			r.minRTT, r.minStamp = rtt, now
		}
		r.rttSinceProbe = true
	} else if r.minRTT == 0 || rtt < r.minRTT {
		return // RFC 8985 section 6.2: ambiguous retransmission ACK.
	}
	if !r.forwardSet || after(s.End, r.forward) {
		r.forwardSet = true
		r.forward = s.End
	} else if before(s.End, r.forward) && s.Transmissions == 1 {
		r.reordered = true
	}
	r.rtt = rtt
	if r.latest.IsZero() || sentAfter(s.Sent, s.End, r.latest, r.latestEnd) {
		r.latest, r.latestEnd = s.Sent, s.End
	}
}

func sentAfter(t time.Time, end uint32, other time.Time, otherEnd uint32) bool {
	return t.After(other) || t.Equal(other) && after(end, otherEnd)
}

func (r *rack) Evaluate(e Event, flight Flight) Decision {
	if !e.SACK {
		return (&classic{}).Evaluate(e, flight)
	}
	var d Decision
	n := flight.Len()
	if e.SRTT > 0 && !r.probed {
		r.rttSinceProbe = true
	}
	if r.dsackRoundSet && !before(e.Una, r.dsackRound) {
		r.dsackRoundSet = false
	}
	if e.Kind == ACK && e.DSACK && !r.dsackRoundSet {
		r.reordered = true
		r.multiplier = min(r.multiplier+1, 256)
		r.persist = 16
		r.dsackRound, r.dsackRoundSet = e.Next, true
	} else if e.RecoveryDone && r.persist > 0 {
		r.persist--
		if r.persist == 0 {
			r.multiplier = 1
		}
	}
	if e.Kind == ACK && r.probePending && !before(e.Una, r.probeEnd) {
		if !r.probeRetrans || e.DSACK && e.Duplicate.End == r.probeEnd || e.DupACKs > 0 && !e.HasSACK {
			r.probePending = false
		} else if after(e.Una, r.probeEnd) {
			r.probePending = false
			d.RepairedLoss = true
			d.RepairedBytes = r.probeBytes
		}
	}
	if e.InRecovery || e.Kind == Timeout || e.Kind == Reneging {
		r.pto = time.Time{}
		r.probePending = false
	}
	if e.Acked > 0 && !r.probePending && r.rttSinceProbe {
		r.probed = false
	}
	sacked := 0
	for i := range n {
		if flight.At(i).SACKed {
			sacked++
		}
	}
	window := min(time.Duration(max(r.multiplier, 1))*r.minRTT/4, e.SRTT)
	if !r.reordered && (e.InRecovery || sacked >= 3) {
		window = 0
	}
	var reorderAt time.Time
	for i := range n {
		s := flight.At(i)
		if s.SACKed || s.Lost || s.Repair {
			continue
		}
		due := s.Sent.Add(r.rtt + window)
		if e.Kind == Reneging || e.Kind == Timeout && (s.Start == e.Una || !e.Now.Before(due)) {
			d.lose(s)
		} else if !r.latest.IsZero() && sentAfter(r.latest, r.latestEnd, s.Sent, s.End) {
			// An ACK from the pre-PMTU flight may acknowledge an original
			// packet or a replacement. Its assigned retransmission timestamp
			// is ambiguous even when the sample exceeds minRTT. Require
			// delivery beyond the replacement's flight boundary, or use RTO.
			if s.PMTURepair && !after(r.forward, s.RetransmitEnd) {
				continue
			}

			if !e.Now.Before(due) {

				d.lose(s)
			} else if reorderAt.IsZero() || due.After(reorderAt) {
				reorderAt = due
			}
		}
	}
	if d.Count > 0 || d.More || e.Kind == Timeout || e.Kind == Reneging {
		r.pto = time.Time{}
		return d
	}
	if !reorderAt.IsZero() {
		d.Next = reorderAt
		return d
	}
	if !e.CanProbe || e.InRecovery || sacked > 0 || n == 0 || r.probed || !r.rttSinceProbe {
		r.pto = time.Time{}
		return d
	}
	if r.pto.IsZero() || e.Kind == ACK && e.Acked > 0 {
		interval := 2 * e.SRTT
		if e.SRTT == 0 {
			interval = time.Second
		} else if n == 1 {
			interval += 200 * time.Millisecond
		}
		base := r.lastSent
		if e.Kind == ACK && e.Acked > 0 {
			base = e.Now
		}
		r.pto = earlier(base.Add(interval), e.RTOAt)
	}
	if e.Kind == Timer && !e.Now.Before(r.pto) {
		d.Probe = true
		r.probed = true // Failed output also falls back to RTO, never a PTO loop.
		r.pto = time.Time{}
		return d
	}
	d.Next = r.pto
	return d
}
