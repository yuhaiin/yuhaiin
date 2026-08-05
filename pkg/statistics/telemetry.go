package statistics

import (
	"context"
	"database/sql"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

const telemetryFlushInterval = 15 * time.Second
const telemetryMaintenanceInterval = time.Hour
const telemetryHourlyRetention = 30 * 24 * time.Hour
const telemetryValueIDCacheCapacity = 512

type telemetryDimension struct {
	kind  string
	value string
}

type dimensionCounter struct {
	dimensions []telemetryDimension
	download   atomic.Uint64
	upload     atomic.Uint64
	removed    atomic.Bool
}

type telemetryRecorder struct {
	db              *sql.DB
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	counters        syncmap.SyncMap[*dimensionCounter, struct{}]
	valueIDs        *lru.SyncLru[telemetryDimension, int64]
	flushMu         sync.Mutex
	maintenanceMu   sync.Mutex
	lastMaintenance time.Time
}

func newTelemetryRecorder(db *sql.DB) *telemetryRecorder {
	ctx, cancel := context.WithCancel(context.Background())
	r := &telemetryRecorder{
		db:       db,
		ctx:      ctx,
		cancel:   cancel,
		valueIDs: lru.NewSyncLru(lru.WithCapacity[telemetryDimension, int64](telemetryValueIDCacheCapacity)),
	}
	r.wg.Go(func() {
		ticker := time.NewTicker(telemetryFlushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
				r.flush()
				r.compactOldTelemetry(time.Now())
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
	// Keep the counter registered until the next batch flush so its final
	// traffic delta is persisted without blocking the connection close path.
	counter.removed.Store(true)
}

func (r *telemetryRecorder) RecordFailure(info contractconnection.Connection) {
	dimensions := dimensionsForConnection(info)
	if len(dimensions) == 0 || r.db == nil {
		return
	}
	if err := persistFailureDimensions(context.Background(), r.db, r.valueIDs, dimensions); err != nil {
		log.Warn("persist telemetry failure dimensions failed", "err", err)
	}
}

func (r *telemetryRecorder) Close() {
	r.cancel()
	r.wg.Wait()
	r.flush()
	r.compactOldTelemetry(time.Now())
}

func (r *telemetryRecorder) flush() {
	counters := make([]*dimensionCounter, 0)
	removed := make([]*dimensionCounter, 0)
	r.counters.Range(func(counter *dimensionCounter, _ struct{}) bool {
		counters = append(counters, counter)
		if counter.removed.Load() {
			removed = append(removed, counter)
		}
		return true
	})
	r.flushCounters(counters)
	for _, counter := range removed {
		r.counters.Delete(counter)
	}
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
	if err := persistTrafficDimensions(context.Background(), r.db, r.valueIDs, deltas); err != nil {
		log.Warn("persist telemetry traffic dimensions failed", "err", err)
	}
}

func dimensionsForConnection(info contractconnection.Connection) []telemetryDimension {
	values := map[string]string{
		"protocol":    info.Network.ConnType,
		"inbound":     firstNonEmpty(info.InboundName, info.Inbound),
		"source":      normalizeTelemetrySource(info.Source),
		"addr":        telemetryAddr(info),
		"outbound":    firstNonEmpty(info.NodeName, info.NodeID, info.Outbound),
		"process":     info.Process,
		"tag":         info.Tag,
		"destination": telemetryDestination(info),
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

func telemetryDestination(info contractconnection.Connection) string {
	if info.FakeIP != "" {
		return ""
	}
	if value := firstNonEmpty(info.Domain, info.Hosts); value != "" {
		return value
	}
	if info.Destination != "" {
		return info.Destination
	}
	return info.Addr
}

func telemetryAddr(info contractconnection.Connection) string {
	if info.FakeIP != "" && telemetryHost(info.Addr) == telemetryHost(info.FakeIP) {
		return firstNonEmpty(info.Domain, info.Hosts)
	}
	return info.Addr
}

func telemetryHost(value string) string {
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(value, "[]")
}

func normalizeTelemetrySource(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "http2.h-") {
		if marker := strings.Index(value[len("http2.h-"):], "-2"); marker >= 0 {
			value = value[len("http2.h-")+marker+2:]
		}
	}
	if left := strings.LastIndexByte(value, '['); left >= 0 {
		if right := strings.IndexByte(value[left+1:], ']'); right >= 0 {
			return value[left+1 : left+1+right]
		}
	}

	if strings.Count(value, ":") == 1 {
		colon := strings.LastIndexByte(value, ':')
		if colon > 0 && colon+1 < len(value) && isDecimal(value[colon+1:]) {
			return value[:colon]
		}
	}
	return value
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
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

func persistTrafficDimensions(ctx context.Context, db *sql.DB, valueIDs *lru.SyncLru[telemetryDimension, int64], deltas map[telemetryDimension]contractconnection.Counter) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	bucket := now.UTC().Truncate(time.Hour).Unix()
	for dimension, counter := range deltas {
		valueID, err := telemetryValueID(ctx, tx, valueIDs, dimension)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO traffic_dimension_hourly(bucket_start_utc, value_id, upload_bytes, download_bytes)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(bucket_start_utc, value_id) DO UPDATE SET
				upload_bytes = upload_bytes + excluded.upload_bytes,
				download_bytes = download_bytes + excluded.download_bytes
		`, bucket, valueID, parseUint64(counter.Upload), parseUint64(counter.Download)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func persistFailureDimensions(ctx context.Context, db *sql.DB, valueIDs *lru.SyncLru[telemetryDimension, int64], dimensions []telemetryDimension) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	bucket := now.UTC().Truncate(time.Hour).Unix()
	for _, dimension := range dimensions {
		valueID, err := telemetryValueID(ctx, tx, valueIDs, dimension)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO failure_dimension_hourly(bucket_start_utc, value_id, failed_count)
			VALUES (?, ?, 1)
			ON CONFLICT(bucket_start_utc, value_id) DO UPDATE SET
				failed_count = failed_count + 1
		`, bucket, valueID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func telemetryValueID(ctx context.Context, tx *sql.Tx, cache *lru.SyncLru[telemetryDimension, int64], dimension telemetryDimension) (int64, error) {
	if value, ok := cache.Load(dimension); ok {
		return value, nil
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO telemetry_dimension_values(dimension, value)
		VALUES (?, ?)
		ON CONFLICT(dimension, value) DO NOTHING
	`, dimension.kind, dimension.value); err != nil {
		return 0, err
	}

	var id int64
	if err := tx.QueryRowContext(ctx, `
		SELECT id
		FROM telemetry_dimension_values
		WHERE dimension = ? AND value = ?
	`, dimension.kind, dimension.value).Scan(&id); err != nil {
		return 0, err
	}
	cache.Add(dimension, id)
	return id, nil
}

func (r *telemetryRecorder) compactOldTelemetry(now time.Time) {
	if r.db == nil {
		return
	}
	r.maintenanceMu.Lock()
	defer r.maintenanceMu.Unlock()
	if !r.lastMaintenance.IsZero() && now.Sub(r.lastMaintenance) < telemetryMaintenanceInterval {
		return
	}
	r.lastMaintenance = now

	cutoff := now.UTC().Truncate(time.Hour).Add(-telemetryHourlyRetention).Unix()
	tx, err := r.db.BeginTx(context.Background(), nil)
	if err != nil {
		log.Warn("begin telemetry maintenance failed", "err", err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	for _, tables := range [][2]string{
		{"traffic_dimension_hourly", "traffic_dimension_daily"},
		{"failure_dimension_hourly", "failure_dimension_daily"},
	} {
		var insert string
		if tables[0] == "traffic_dimension_hourly" {
			insert = `
				INSERT INTO traffic_dimension_daily(bucket_start_utc, value_id, upload_bytes, download_bytes)
				SELECT (bucket_start_utc / 86400) * 86400, value_id, SUM(upload_bytes), SUM(download_bytes)
				FROM traffic_dimension_hourly
				WHERE bucket_start_utc < ?
				GROUP BY (bucket_start_utc / 86400) * 86400, value_id
				ON CONFLICT(bucket_start_utc, value_id) DO UPDATE SET
					upload_bytes = upload_bytes + excluded.upload_bytes,
					download_bytes = download_bytes + excluded.download_bytes`
		} else {
			insert = `
				INSERT INTO failure_dimension_daily(bucket_start_utc, value_id, failed_count)
				SELECT (bucket_start_utc / 86400) * 86400, value_id, SUM(failed_count)
				FROM failure_dimension_hourly
				WHERE bucket_start_utc < ?
				GROUP BY (bucket_start_utc / 86400) * 86400, value_id
				ON CONFLICT(bucket_start_utc, value_id) DO UPDATE SET
					failed_count = failed_count + excluded.failed_count`
		}
		if _, err := tx.ExecContext(context.Background(), insert, cutoff); err != nil {
			log.Warn("roll up telemetry history failed", "table", tables[0], "err", err)
			return
		}
		if _, err := tx.ExecContext(context.Background(), "DELETE FROM "+tables[0]+" WHERE bucket_start_utc < ?", cutoff); err != nil {
			log.Warn("delete rolled up telemetry history failed", "table", tables[0], "err", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Warn("commit telemetry maintenance failed", "err", err)
	}
}

func normalizePersistedFakeIPDestinations(db *sql.DB) {
	if db == nil {
		return
	}
	ctx := context.Background()
	var normalized string
	if err := db.QueryRowContext(ctx, `
		SELECT value FROM metadata WHERE key = 'telemetry_fakeip_destination_normalized'
	`).Scan(&normalized); err == nil && normalized == "1" {
		return
	}
	fakeIPs := make(map[string]string)
	rows, err := db.QueryContext(ctx, `SELECT ip, domain FROM fakeip_entries ORDER BY last_used_at DESC`)
	if err != nil {
		log.Warn("load fakeip telemetry mappings failed", "err", err)
		return
	}
	for rows.Next() {
		var raw []byte
		var domain string
		if err := rows.Scan(&raw, &domain); err != nil {
			_ = rows.Close()
			log.Warn("scan fakeip telemetry mapping failed", "err", err)
			return
		}
		if addr, ok := netip.AddrFromSlice(raw); ok {
			if _, exists := fakeIPs[addr.String()]; !exists {
				fakeIPs[addr.String()] = domain
			}
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		log.Warn("iterate fakeip telemetry mappings failed", "err", err)
		return
	}
	_ = rows.Close()
	if len(fakeIPs) == 0 {
		return
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Warn("begin fakeip telemetry normalization failed", "err", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	rows, err = tx.QueryContext(ctx, `
		SELECT id, value
		FROM telemetry_dimension_values
		WHERE dimension = 'destination'
	`)
	if err != nil {
		log.Warn("load destination telemetry values failed", "err", err)
		return
	}
	type destinationValue struct {
		id    int64
		value string
	}
	values := make([]destinationValue, 0)
	for rows.Next() {
		var value destinationValue
		if err := rows.Scan(&value.id, &value.value); err != nil {
			_ = rows.Close()
			log.Warn("scan destination telemetry value failed", "err", err)
			return
		}
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		log.Warn("iterate destination telemetry values failed", "err", err)
		return
	}
	_ = rows.Close()

	for _, value := range values {
		host, _, err := net.SplitHostPort(value.value)
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			continue
		}
		_, ok := fakeIPs[addr.String()]
		if !ok {
			continue
		}
		for _, table := range []string{"traffic_dimension_hourly", "traffic_dimension_daily"} {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE value_id = ?", value.id); err != nil {
				log.Warn("delete fakeip traffic destination failed", "table", table, "err", err)
				return
			}
		}
		for _, table := range []string{"failure_dimension_hourly", "failure_dimension_daily"} {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE value_id = ?", value.id); err != nil {
				log.Warn("delete fakeip failure destination failed", "table", table, "err", err)
				return
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM telemetry_dimension_values WHERE id = ?`, value.id); err != nil {
			log.Warn("delete fakeip telemetry value failed", "err", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Warn("commit fakeip telemetry normalization failed", "err", err)
		return
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO metadata(key, value)
		VALUES ('telemetry_fakeip_destination_normalized', '1')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`); err != nil {
		log.Warn("mark fakeip telemetry normalization failed", "err", err)
	}
}
