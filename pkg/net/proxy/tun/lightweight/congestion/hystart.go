package congestion

import "time"

// hystart implements RFC 9406's delay-based exit and Conservative Slow Start.
// Rounds end at a captured SND.NXT; delivery counters cannot substitute for
// sequence space because selective ACKs can arrive beyond a cumulative hole.
type hystart struct {
	initialized                   bool
	end                           uint32
	lastMin, currentMin, baseline time.Duration
	samples, cssRounds            int
	css                           bool
}

func (h *hystart) ack(e AckEvent, mss uint64) (growth uint64, exit bool) {
	// Reno/CUBIC are unpaced, so RFC 9406 caps stretch-ACK growth at 8 SMSS.
	growth = min(e.AckedBytes, 8*mss)
	if h.css {
		growth /= 4
	}
	if !h.initialized {
		// Skip handshake/control-only ACKs and legacy events without sequence
		// information. They still receive normal slow-start byte growth.
		if e.AckedBytes <= 1 || e.ACK == 0 && e.NextSeq == 0 {
			return growth, false
		}
		h.initialized = true
		h.end = e.NextSeq
	}
	if e.RTT > 0 {
		if h.currentMin == 0 || e.RTT < h.currentMin {
			h.currentMin = e.RTT
		}
		h.samples++
	}
	if h.css {
		if h.samples >= 8 && h.currentMin < h.baseline {
			h.css = false
			h.cssRounds = 0
			h.baseline = 0
		}
	} else if h.samples >= 8 && h.lastMin > 0 {
		threshold := max(4*time.Millisecond, min(h.lastMin/8, 16*time.Millisecond))
		if h.currentMin >= h.lastMin+threshold {
			h.css = true
			h.cssRounds = 0
			h.baseline = h.currentMin
		}
	}
	if int32(e.ACK-h.end) >= 0 {
		if h.css {
			h.cssRounds++
			if h.cssRounds == 5 {
				exit = true
				h.css = false
			}
		}
		h.lastMin = h.currentMin
		h.currentMin = 0
		h.samples = 0
		h.end = e.NextSeq
	}
	return growth, exit
}
func (h *hystart) reset() { *h = hystart{} }
