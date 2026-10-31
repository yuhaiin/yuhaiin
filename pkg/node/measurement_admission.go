package node

import (
	"context"
	"errors"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

var errMeasurementBusy = errors.New("measurement concurrency limit reached")

// Manual and periodic network measurements share this bounded admission.
// The speed-test subgroup and scheduler group limits remain additional caps.
func (r *NodeRuntime) admitMeasurement(ctx context.Context, nodeID string) (*measurementLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.measurementMu.Lock()
	defer r.measurementMu.Unlock()
	if r.measurementClosed {
		return nil, errors.New("node runtime is closed")
	}
	if r.measurementActive.Load() >= r.measurementLimit.Load() {
		return nil, errMeasurementBusy
	}
	ctx, cancel := context.WithCancel(ctx)
	l := &measurementLease{ctx: ctx, cancel: cancel, runtime: r, nodeID: nodeID}
	if r.measurements == nil {
		r.measurements = make(map[*measurementLease]struct{})
	}
	r.measurements[l] = struct{}{}
	r.measurementActive.Add(1)
	return l, nil
}

type measurementLease struct {
	ctx     context.Context
	cancel  context.CancelFunc
	runtime *NodeRuntime
	nodeID  string
	once    sync.Once
}

func (l *measurementLease) release() {
	l.once.Do(func() {
		l.cancel()
		r := l.runtime
		r.measurementMu.Lock()
		delete(r.measurements, l)
		r.measurementActive.Add(-1)
		r.measurementMu.Unlock()
	})
}
func (r *NodeRuntime) cancelMeasurements(nodeID string) {
	if nodeID == "" {
		return
	}
	r.measurementMu.Lock()
	defer r.measurementMu.Unlock()
	for lease := range r.measurements {
		if lease.nodeID == nodeID {
			lease.cancel()
		}
	}
}
func (r *NodeRuntime) stopMeasurements() {
	r.measurementMu.Lock()
	defer r.measurementMu.Unlock()
	r.measurementClosed = true
	for lease := range r.measurements {
		lease.cancel()
	}
}

func (s *selectorRuntime) waitProbeBudget(ctx context.Context, bandwidth int64) error {
	s.mu.Lock()
	limiter := s.probeLimiter
	override := s.probeRateOverrides[bandwidth]
	s.mu.Unlock()
	if override != nil {
		if err := override.WaitN(ctx, int(probeByteBudget)); err != nil {
			return errors.Join(trafficcontrol.ErrLocalLimit, err)
		}
	}
	if err := limiter.WaitN(ctx, int(probeByteBudget)); err != nil {
		return errors.Join(trafficcontrol.ErrLocalLimit, err)
	}
	return nil
}
