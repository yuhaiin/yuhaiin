package node

import (
	"math"
	"strconv"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

const passiveRateWindow = time.Minute
const passiveRateFreshness = 2 * nodeMetricsInterval

// The existing observer is the sole producer. Readers see only an immutable
// atomic snapshot; forwarding retains its existing byte-counter increments.
type nodeTrafficWindow struct {
	buckets [12]trafficBucket
	next    int
}
type trafficBucket struct {
	start, end       time.Time
	upload, download uint64
}

func (n *nodeCounters) sampleTraffic(start, end time.Time, previous [2]uint64, current nodeTotals) {
	elapsed := end.Sub(start)
	wallMS := end.UnixMilli() - start.UnixMilli()
	reliable := wallMS > 0 && wallMS <= passiveRateFreshness.Milliseconds() && reliableTrafficSpan(elapsed, time.Duration(wallMS)*time.Millisecond)
	if !reliable || current.UploadBytes < previous[0] || current.DownloadBytes < previous[1] {
		n.trafficWindow = nodeTrafficWindow{}
		n.window.Store(nil)
		return
	}
	w := &n.trafficWindow
	w.buckets[w.next] = trafficBucket{start: start, end: end, upload: current.UploadBytes - previous[0], download: current.DownloadBytes - previous[1]}
	w.next = (w.next + 1) % len(w.buckets)
	cutoff := end.Add(-passiveRateWindow)
	var upload, download, seconds float64
	for _, bucket := range w.buckets {
		if bucket.start.IsZero() || !bucket.end.After(cutoff) || bucket.end.After(end) {
			continue
		}
		from := bucket.start
		if from.Before(cutoff) {
			from = cutoff
		}
		span := bucket.end.Sub(from).Seconds()
		fraction := span / bucket.end.Sub(bucket.start).Seconds()
		upload += float64(bucket.upload) * fraction
		download += float64(bucket.download) * fraction
		seconds += span
	}
	if seconds <= 0 {
		n.window.Store(nil)
		return
	}
	n.window.Store(&contract.TrafficWindow{At: end.UnixMilli(), WindowMS: min(int64(math.Round(seconds*1000)), passiveRateWindow.Milliseconds()),
		UploadBps: strconv.FormatFloat(math.Floor(upload/seconds), 'f', 0, 64), DownloadBps: strconv.FormatFloat(math.Floor(download/seconds), 'f', 0, 64)})
}

// A platform's monotonic clock can pause during suspend. Compare wall time as
// well to reset stale samples after resume.
func reliableTrafficSpan(elapsed, wall time.Duration) bool {
	if elapsed <= 0 || elapsed > passiveRateFreshness || wall <= 0 || wall > passiveRateFreshness {
		return false
	}
	drift := elapsed - wall
	return drift >= -time.Second && drift <= time.Second
}
func (n *nodeCounters) freshTrafficWindow(now int64) *contract.TrafficWindow {
	value := n.window.Load()
	if value == nil || value.At > now || now-value.At > passiveRateFreshness.Milliseconds() {
		return nil
	}
	return new(*value)
}

// These are dial outcomes from the existing bounded health history, not a count
// of unique application sessions: later I/O failures and response/probe events
// must not double-count a successful dial or imply UDP remote reachability.
func recentTCPDials(health contract.ChannelHealth, now int64) *contract.DialObservationWindow {
	value := contract.DialObservationWindow{WindowMS: recentNodeObservation.Milliseconds(), SampleLimit: 64}
	for _, sample := range health.Samples[max(0, len(health.Samples)-64):] {
		if sample.Kind != "connect" || sample.At <= 0 || sample.At > now || now-sample.At > value.WindowMS {
			continue
		}
		value.Samples++
		if !sample.OK {
			value.Failures++
		}
	}
	if value.Samples == 0 {
		return nil
	}
	value.FailureRate = float64(value.Failures) / float64(value.Samples)
	return &value
}
