package node

import (
	"context"
	"errors"
	"slices"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
)

var errSpeedBusy = errors.New("speed test concurrency limit reached")
var errSpeedBudget = errors.New("daily speed test traffic budget exhausted")

func (r *NodeRuntime) Speed(ctx context.Context, id string, request contract.SpeedTestRequest) (contract.ThroughputMeasurement, error) {
	request, err := latency.ValidateSpeedTest(request)
	if err != nil {
		return contract.ThroughputMeasurement{}, err
	}
	nodes, err := r.openNodes(ctx)
	if err != nil {
		return contract.ThroughputMeasurement{}, err
	}
	select {
	case r.speedSlots <- struct{}{}:
		defer func() { <-r.speedSlots }()
	default:
		return contract.ThroughputMeasurement{}, errSpeedBusy
	}
	n, err := nodes.Get(ctx, id)
	if err != nil {
		return contract.ThroughputMeasurement{}, err
	}
	if !n.Enabled {
		return contract.ThroughputMeasurement{}, errors.New("speed test node is disabled")
	}
	// Reserve the whole byte budget durably before touching the network. Failed
	// and cancelled tests consume the reservation; restarting cannot reset it.
	day := time.Now().UTC().Unix() / 86400
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return contract.ThroughputMeasurement{}, errors.New("node runtime is closed")
	}
	db := r.sqlite.DB()
	r.mu.Unlock()
	result, err := db.ExecContext(ctx, `INSERT INTO node_speed_budget(id,day,reserved_bytes) VALUES(1,?,?)
	 ON CONFLICT(id) DO UPDATE SET day=excluded.day,
	 reserved_bytes=CASE WHEN day=excluded.day THEN reserved_bytes+excluded.reserved_bytes ELSE excluded.reserved_bytes END
	 WHERE (CASE WHEN day=excluded.day THEN reserved_bytes ELSE 0 END)+excluded.reserved_bytes<=?`, day, request.MaxBytes, request.DailyBudgetBytes)
	if err != nil {
		return contract.ThroughputMeasurement{}, err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return contract.ThroughputMeasurement{}, errSpeedBudget
	}
	proxy, err := r.getContractDialer(ctx, id, n)
	if err != nil {
		return contract.ThroughputMeasurement{}, err
	}
	measurement, err := latency.MeasureDownload(ctx, proxy, request)
	measurement.At, measurement.Target = time.Now().UnixMilli(), request.URL
	if err != nil {
		measurement.OK = false
		measurement.Error = "speed measurement failed"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return measurement, ctx.Err()
	}
	c := r.observer.counter(id)
	c.mu.Lock()
	c.throughputHistory = append(c.throughputHistory, measurement)
	if len(c.throughputHistory) > 16 {
		c.throughputHistory = slices.Delete(c.throughputHistory, 0, len(c.throughputHistory)-16)
	}
	old := c.throughput
	if measurement.OK && old.OK && old.Target == measurement.Target && measurement.At-old.At >= 0 && measurement.At-old.At < recentNodeObservation.Milliseconds() {
		measurement.Samples = min(old.Samples+1, 64)
		measurement.DownloadMbps = .8*old.DownloadMbps + .2*measurement.DownloadMbps
	}
	c.throughput = measurement
	c.mu.Unlock()
	// Endpoint HTTP status, body budget and intentional duration truncation are
	// not transport health failures. The observedProxy records real dial errors.
	return measurement, err
}
