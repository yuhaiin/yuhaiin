package statistics

import (
	"context"
	"database/sql"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

const telemetryFlushInterval = 15 * time.Second

type telemetryDimension struct {
	kind  string
	value string
}

type dimensionCounter struct {
	dimensions []telemetryDimension
	download   atomic.Uint64
	upload     atomic.Uint64
}

type telemetryRecorder struct {
	db       *sql.DB
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	counters sync.Map // map[*dimensionCounter]struct{}
	flushMu  sync.Mutex
}

func newTelemetryRecorder(db *sql.DB) *telemetryRecorder {
	ctx, cancel := context.WithCancel(context.Background())
	r := &telemetryRecorder{db: db, ctx: ctx, cancel: cancel}
	r.wg.Go(func() {
		ticker := time.NewTicker(telemetryFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
				r.flush()
			}
		}
	})
	return r
}

func (r *telemetryRecorder) Register(info contractconnection.Connection) *dimensionCounter {
	counter := &dimensionCounter{dimensions: dimensionsForConnection(info)}
	if len(counter.dimensions) != 0 {
		r.counters.Store(counter, struct{}{})
	}
	return counter
}

func (r *telemetryRecorder) Remove(counter *dimensionCounter) {
	if counter == nil {
		return
	}
	r.flushCounters([]*dimensionCounter{counter})
	r.counters.Delete(counter)
}

func (r *telemetryRecorder) RecordFailure(info contractconnection.Connection) {
	dimensions := dimensionsForConnection(info)
	if len(dimensions) == 0 || r.db == nil {
		return
	}
	if err := persistFailureDimensions(context.Background(), r.db, dimensions); err != nil {
		log.Warn("persist telemetry failure dimensions failed", "err", err)
	}
}

func (r *telemetryRecorder) Close() {
	r.cancel()
	r.wg.Wait()
	r.flush()
}

func (r *telemetryRecorder) flush() {
	counters := make([]*dimensionCounter, 0)
	r.counters.Range(func(key, _ any) bool {
		counters = append(counters, key.(*dimensionCounter))
		return true
	})
	r.flushCounters(counters)
}

func (r *telemetryRecorder) flushCounters(counters []*dimensionCounter) {
	if r.db == nil || len(counters) == 0 {
		return
	}
	r.flushMu.Lock()
	defer r.flushMu.Unlock()

	deltas := make(map[telemetryDimension]contractconnection.Counter)
	for _, counter := range counters {
		download := counter.download.Swap(0)
		upload := counter.upload.Swap(0)
		if download == 0 && upload == 0 {
			continue
		}
		for _, dimension := range counter.dimensions {
			current := deltas[dimension]
			current.Download = formatUint64(parseUint64(current.Download) + download)
			current.Upload = formatUint64(parseUint64(current.Upload) + upload)
			deltas[dimension] = current
		}
	}
	if len(deltas) == 0 {
		return
	}
	if err := persistTrafficDimensions(context.Background(), r.db, deltas); err != nil {
		log.Warn("persist telemetry traffic dimensions failed", "err", err)
	}
}

func dimensionsForConnection(info contractconnection.Connection) []telemetryDimension {
	values := map[string]string{
		"protocol":    info.Network.ConnType,
		"inbound":     firstNonEmpty(info.InboundName, info.Inbound),
		"source":      info.Source,
		"addr":        info.Addr,
		"outbound":    firstNonEmpty(info.NodeName, info.NodeID, info.Outbound),
		"process":     info.Process,
		"tag":         info.Tag,
		"destination": firstNonEmpty(info.Domain, info.Hosts, info.Destination, info.Addr),
	}
	for _, match := range info.MatchHistory {
		if match.RuleName != "" {
			values["rule"] = match.RuleName
		}
	}

	keys := make([]string, 0, len(values))
	for key, value := range values {
		if value != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	result := make([]telemetryDimension, 0, len(keys))
	for _, key := range keys {
		result = append(result, telemetryDimension{kind: key, value: values[key]})
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func parseUint64(value string) uint64 {
	var result uint64
	for _, b := range []byte(value) {
		if b < '0' || b > '9' {
			return 0
		}
		result = result*10 + uint64(b-'0')
	}
	return result
}

func persistTrafficDimensions(ctx context.Context, db *sql.DB, deltas map[telemetryDimension]contractconnection.Counter) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	bucket := now.UTC().Truncate(time.Hour).Unix()
	for dimension, counter := range deltas {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO traffic_dimension_hourly(bucket_start_utc, dimension, value, upload_bytes, download_bytes, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(bucket_start_utc, dimension, value) DO UPDATE SET
				upload_bytes = upload_bytes + excluded.upload_bytes,
				download_bytes = download_bytes + excluded.download_bytes,
				updated_at = excluded.updated_at
		`, bucket, dimension.kind, dimension.value, parseUint64(counter.Upload), parseUint64(counter.Download), now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func persistFailureDimensions(ctx context.Context, db *sql.DB, dimensions []telemetryDimension) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	bucket := now.UTC().Truncate(time.Hour).Unix()
	for _, dimension := range dimensions {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO failure_dimension_hourly(bucket_start_utc, dimension, value, failed_count, updated_at)
			VALUES (?, ?, ?, 1, ?)
			ON CONFLICT(bucket_start_utc, dimension, value) DO UPDATE SET
				failed_count = failed_count + 1,
				updated_at = excluded.updated_at
		`, bucket, dimension.kind, dimension.value, now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
