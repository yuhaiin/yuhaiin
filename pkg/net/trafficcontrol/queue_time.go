package trafficcontrol

import "time"

// Store queue timestamps as offsets from a monotonic epoch. This avoids wall
// clock reads and copying time.Time through every packet and scheduling layer.
// Public deterministic queue methods still accept time.Time for callers/tests.
var queueEpoch = time.Now()

func queueNow() time.Duration              { return time.Since(queueEpoch) }
func queueTime(at time.Time) time.Duration { return at.Sub(queueEpoch) }
