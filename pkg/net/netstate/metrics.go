package netstate

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// All label values are fixed at initialization; no network/user identifiers
// enter the metrics. Cached counters avoid label lookup on notification storms.
var lifecycleEvents = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "yuhaiin_network_lifecycle_events_total",
	Help: "Network lifecycle observations and selective resource recovery outcomes.",
}, []string{"kind"})

var (
	RouteEvents       = lifecycleEvents.WithLabelValues("route_only")
	TransitionEvents  = lifecycleEvents.WithLabelValues("transition")
	DuplicateEvents   = lifecycleEvents.WithLabelValues("duplicate")
	Invalidations     = lifecycleEvents.WithLabelValues("resource_invalidation")
	DNSCancellations  = lifecycleEvents.WithLabelValues("dns_cancellation")
	RecoveryAttempts  = lifecycleEvents.WithLabelValues("recovery_attempt")
	RecoverySuccesses = lifecycleEvents.WithLabelValues("recovery_success")
	RecoveryFailures  = lifecycleEvents.WithLabelValues("recovery_failure")
)
