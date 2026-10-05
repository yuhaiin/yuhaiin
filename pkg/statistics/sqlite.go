package statistics

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

type TrafficBucket struct {
	StartUTC      time.Time
	UploadBytes   uint64
	DownloadBytes uint64
}

const storeSessionSQL = `
		INSERT INTO connection_sessions(
			id, opened_at, last_seen_at, state, protocol, process_name, inbound,
			inbound_name, outbound, network, destination, host, summary_json
		)
		VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			last_seen_at = excluded.last_seen_at,
			state = 'open',
			protocol = excluded.protocol,
			process_name = excluded.process_name,
			inbound = excluded.inbound,
			inbound_name = excluded.inbound_name,
			outbound = excluded.outbound,
			network = excluded.network,
			destination = excluded.destination,
			host = excluded.host,
			summary_json = excluded.summary_json
	`

const storeHistorySQL = `
		INSERT INTO connection_history(protocol, addr, process_name, hit_count, last_seen_at, last_connection_json)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(protocol, addr, process_name) DO UPDATE SET
			hit_count = hit_count + excluded.hit_count,
			last_seen_at = excluded.last_seen_at,
			last_connection_json = excluded.last_connection_json
	`

const deleteSessionSQL = `DELETE FROM connection_sessions WHERE id = ?`

type sqliteInfoStore struct {
	db         *sql.DB
	storeStmt  *sql.Stmt
	deleteStmt *sql.Stmt
}

// clearPreviousSessions removes metadata for connections owned by an earlier
// process. Connection history is persisted separately in connection_history.
func clearPreviousSessions(db *sql.DB) {
	if db == nil {
		return
	}

	if _, err := db.ExecContext(context.Background(), `DELETE FROM connection_sessions`); err != nil {
		log.Warn("clear previous connection sessions failed", "err", err)
	}
}

func newSQLiteInfoStore(db *sql.DB) *sqliteInfoStore {
	return &sqliteInfoStore{db: db, storeStmt: prepareStatisticStatement(db, storeSessionSQL), deleteStmt: prepareStatisticStatement(db, deleteSessionSQL)}
}

func (s *sqliteInfoStore) Load(id uint64) (contractconnection.Connection, bool) {
	if s.db == nil {
		return contractconnection.Connection{}, false
	}

	ctx := context.Background()
	var data string
	err := s.db.QueryRowContext(ctx, `
		SELECT summary_json
		FROM connection_sessions
		WHERE id = ?
	`, id).Scan(&data)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Warn("load sqlite connection session failed", "id", id, "err", err)
		}
		return contractconnection.Connection{}, false
	}

	var info contractconnection.Connection
	if err := decodeStatisticJSON(data, &info); err != nil {
		log.Warn("decode sqlite connection session failed", "id", id, "err", err)
		return contractconnection.Connection{}, false
	}
	return info, true
}

func (s *sqliteInfoStore) Store(id uint64, info contractconnection.Connection) {
	if s.db == nil {
		return
	}

	ctx := context.Background()
	data, err := encodeStatisticJSON(&info)
	if err != nil {
		log.Warn("encode sqlite connection session failed", "id", id, "err", err)
		return
	}

	if err := s.storeEncoded(ctx, nil, id, info, data, time.Now().Unix()); err != nil {
		log.Warn("store sqlite connection session failed", "id", id, "err", err)
	}
}

func (s *sqliteInfoStore) storeEncoded(ctx context.Context, tx *sql.Tx, id uint64, info contractconnection.Connection, data string, now int64) error {
	return execStatisticStatement(ctx, tx, s.storeStmt, s.db, storeSessionSQL, id, now, now, info.Network.ConnType, info.Process, info.Inbound,
		info.InboundName, info.Outbound, info.Network.ConnType, info.Destination, info.Addr, data)
}

func (s *sqliteInfoStore) Delete(id uint64) {
	if s.db == nil {
		return
	}

	if err := execStatisticStatement(context.Background(), nil, s.deleteStmt, s.db, deleteSessionSQL, id); err != nil {
		log.Warn("delete sqlite connection session failed", "id", id, "err", err)
	}
}

func (s *sqliteInfoStore) Close() error {
	return errors.Join(closeStatisticStatement(s.storeStmt), closeStatisticStatement(s.deleteStmt))
}

type SQLiteHistory struct {
	db       *sql.DB
	closeDB  func() error
	pushStmt *sql.Stmt
}

func NewSQLiteHistory(path string) *SQLiteHistory {
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, path)
	if err != nil {
		log.Warn("open sqlite history failed", "err", err)
		return newSQLiteHistory(nil)
	}
	return newSQLiteHistoryWithClose(store.DB(), store.Close)
}

func newSQLiteHistory(db *sql.DB) *SQLiteHistory {
	return &SQLiteHistory{db: db, pushStmt: prepareStatisticStatement(db, storeHistorySQL)}
}

func newSQLiteHistoryWithClose(db *sql.DB, closeDB func() error) *SQLiteHistory {
	h := newSQLiteHistory(db)
	h.closeDB = closeDB
	return h
}

func (h *SQLiteHistory) Push(c contractconnection.Connection) {
	if h.db == nil {
		return
	}

	ctx := context.Background()
	data, err := encodeStatisticJSON(&c)
	if err != nil {
		log.Warn("encode sqlite history failed", "err", err)
		return
	}

	if err := h.pushEncoded(ctx, nil, c, data, time.Now().Unix()); err != nil {
		log.Warn("store sqlite history failed", "err", err)
	}
}

func (h *SQLiteHistory) pushEncoded(ctx context.Context, tx *sql.Tx, c contractconnection.Connection, data string, now int64) error {
	return h.pushCountEncoded(ctx, tx, c, data, now, 1)
}

func (h *SQLiteHistory) pushCountEncoded(ctx context.Context, tx *sql.Tx, c contractconnection.Connection, data string, now int64, count uint64) error {
	return execStatisticStatement(ctx, tx, h.pushStmt, h.db, storeHistorySQL, c.Network.ConnType, c.Addr, c.Process, count, now, data)
}

func (h *SQLiteHistory) Get() contractconnection.AllHistoryList {
	if h.db == nil {
		return contractconnection.AllHistoryList{}
	}

	ctx := context.Background()
	rows, err := h.db.QueryContext(ctx, `
		SELECT hit_count, last_seen_at, last_connection_json
		FROM connection_history
		ORDER BY last_seen_at DESC
		LIMIT ?
	`, configuration.HistorySize)
	if err != nil {
		log.Warn("query sqlite history failed", "err", err)
		return contractconnection.AllHistoryList{}
	}
	defer rows.Close()

	var objects []contractconnection.AllHistory
	dumpProcess := false
	for rows.Next() {
		var count uint64
		var lastSeen int64
		var data string
		if err := rows.Scan(&count, &lastSeen, &data); err != nil {
			log.Warn("scan sqlite history failed", "err", err)
			continue
		}

		var info contractconnection.Connection
		if err := decodeStatisticJSON(data, &info); err != nil {
			log.Warn("decode sqlite history failed", "err", err)
			continue
		}
		if !dumpProcess && info.Process != "" {
			dumpProcess = true
		}
		objects = append(objects, contractconnection.AllHistory{
			Count:      formatUint64(count),
			Time:       time.Unix(lastSeen, 0),
			Connection: info,
		})
	}

	return contractconnection.AllHistoryList{
		Items:              objects,
		DumpProcessEnabled: dumpProcess,
	}
}

func (h *SQLiteHistory) Close() error {
	err := closeStatisticStatement(h.pushStmt)
	if h.closeDB != nil {
		err = errors.Join(err, h.closeDB())
	}
	return err
}

type failedHistoryKey struct {
	protocol string
	host     string
	process  string
}

type failedHistoryPending struct {
	count    uint64
	lastSeen int64
	lastErr  string
}

type SQLiteFailedHistory struct {
	db      *sql.DB
	closeDB func() error

	mu        sync.Mutex
	pending   map[failedHistoryKey]failedHistoryPending
	trigger   chan struct{}
	stop      chan struct{}
	done      chan struct{}
	flushMu   sync.Mutex
	closeOnce sync.Once
}

func NewSQLiteFailedHistory(path string) *SQLiteFailedHistory {
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, path)
	if err != nil {
		log.Warn("open sqlite failed history failed", "err", err)
		return newSQLiteFailedHistory(nil)
	}
	h := newSQLiteFailedHistory(store.DB())
	h.closeDB = store.Close
	return h
}

func newSQLiteFailedHistory(db *sql.DB) *SQLiteFailedHistory {
	h := &SQLiteFailedHistory{db: db}
	if db != nil {
		h.pending = make(map[failedHistoryKey]failedHistoryPending)
		h.trigger = make(chan struct{}, 1)
		h.stop = make(chan struct{})
		h.done = make(chan struct{})
		go h.run()
	}
	return h
}

func (h *SQLiteFailedHistory) run() {
	runPersistenceWorker(h.stop, h.trigger, h.done, 2*time.Second,
		func() bool {
			h.mu.Lock()
			defer h.mu.Unlock()
			return len(h.pending) >= sqlitePersistenceBatchSize
		},
		h.flush, "failed history")
}

func (h *SQLiteFailedHistory) Push(ctx context.Context, err error, protocol string, host netapi.Address) {
	if err == nil || netapi.IsBlockError(err) {
		return
	}

	storeContext := netapi.GetContext(ctx)
	if de, ok := errors.AsType[*netapi.DialError](err); ok && de.Err != nil {
		err = de.Err
	}
	if ne, ok := errors.AsType[*net.OpError](err); ok {
		err = ne.Err
	}
	if h.db == nil {
		return
	}

	key := failedHistoryKey{
		protocol: protocol,
		host:     getRealAddr(storeContext, host),
		process:  storeContext.GetProcessName(),
	}
	now := time.Now().Unix()
	h.mu.Lock()
	pending := h.pending[key]
	pending.count++
	pending.lastSeen = now
	pending.lastErr = err.Error()
	h.pending[key] = pending
	h.mu.Unlock()

	select {
	case h.trigger <- struct{}{}:
	default:
	}
}

func (h *SQLiteFailedHistory) flush() error {
	if h == nil || h.db == nil {
		return nil
	}
	h.flushMu.Lock()
	defer h.flushMu.Unlock()

	h.mu.Lock()
	if len(h.pending) == 0 {
		h.mu.Unlock()
		return nil
	}
	pending := h.pending
	h.pending = make(map[failedHistoryKey]failedHistoryPending)
	h.mu.Unlock()

	tx, err := h.db.BeginTx(context.Background(), nil)
	if err != nil {
		h.requeue(pending)
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(context.Background(), `
		INSERT INTO failed_connection_history(protocol, host, process_name, failed_count, last_seen_at, last_error)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(protocol, host, process_name) DO UPDATE SET
			failed_count = failed_count + excluded.failed_count,
			last_seen_at = excluded.last_seen_at,
			last_error = excluded.last_error
	`)
	if err != nil {
		h.requeue(pending)
		return err
	}
	defer stmt.Close()
	for key, value := range pending {
		if _, err := stmt.ExecContext(context.Background(), key.protocol, key.host, key.process, value.count, value.lastSeen, value.lastErr); err != nil {
			h.requeue(pending)
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		h.requeue(pending)
		return err
	}
	return nil
}

func (h *SQLiteFailedHistory) requeue(pending map[failedHistoryKey]failedHistoryPending) {
	h.mu.Lock()
	for key, value := range pending {
		current := h.pending[key]
		current.count += value.count
		if value.lastSeen > current.lastSeen {
			current.lastSeen = value.lastSeen
			current.lastErr = value.lastErr
		}
		h.pending[key] = current
	}
	h.mu.Unlock()
}

func (h *SQLiteFailedHistory) Get() contractconnection.FailedHistoryList {
	if h.db == nil {
		return contractconnection.FailedHistoryList{}
	}

	if err := h.flush(); err != nil {
		log.Warn("flush sqlite failed history before query failed", "err", err)
	}
	ctx := context.Background()
	rows, err := h.db.QueryContext(ctx, `
		SELECT protocol, host, process_name, failed_count, last_seen_at, last_error
		FROM failed_connection_history
		ORDER BY last_seen_at DESC
		LIMIT ?
	`, configuration.HistorySize)
	if err != nil {
		log.Warn("query sqlite failed history failed", "err", err)
		return contractconnection.FailedHistoryList{}
	}
	defer rows.Close()

	var objects []contractconnection.FailedHistory
	dumpProcess := false
	for rows.Next() {
		var protocol string
		var host, process, lastError string
		var failedCount uint64
		var lastSeen int64
		if err := rows.Scan(&protocol, &host, &process, &failedCount, &lastSeen, &lastError); err != nil {
			log.Warn("scan sqlite failed history failed", "err", err)
			continue
		}

		if !dumpProcess && process != "" {
			dumpProcess = true
		}
		objects = append(objects, contractconnection.FailedHistory{
			Protocol:    protocol,
			Host:        host,
			Error:       lastError,
			Process:     process,
			Time:        time.Unix(lastSeen, 0),
			FailedCount: formatUint64(failedCount),
		})
	}

	return contractconnection.FailedHistoryList{
		Items:              objects,
		DumpProcessEnabled: dumpProcess,
	}
}

func (h *SQLiteFailedHistory) Close() error {
	if h == nil {
		return nil
	}
	var err error
	h.closeOnce.Do(func() {
		if h.stop != nil {
			close(h.stop)
			<-h.done
		}
		if flushErr := h.flush(); flushErr != nil {
			err = flushErr
		}
		if h.closeDB != nil {
			err = errors.Join(err, h.closeDB())
		}
	})
	return err
}

func encodeStatisticJSON(msg any) (string, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeStatisticJSON(data string, msg any) error {
	return json.Unmarshal([]byte(data), msg)
}

func (c *Connections) TrafficHourly(ctx context.Context, from, to time.Time) ([]TrafficBucket, error) {
	return c.trafficAggregate(ctx, from, to, func(t time.Time) time.Time {
		return t.UTC().Truncate(time.Hour)
	})
}

func (c *Connections) TrafficDaily(ctx context.Context, from, to time.Time) ([]TrafficBucket, error) {
	return c.trafficAggregate(ctx, from, to, func(t time.Time) time.Time {
		y, m, d := t.UTC().Date()
		return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	})
}

func (c *Connections) TrafficMonthly(ctx context.Context, from, to time.Time) ([]TrafficBucket, error) {
	return c.trafficAggregate(ctx, from, to, func(t time.Time) time.Time {
		y, m, _ := t.UTC().Date()
		return time.Date(y, m, 1, 0, 0, 0, 0, time.UTC)
	})
}

func (c *Connections) TrafficYearly(ctx context.Context, from, to time.Time) ([]TrafficBucket, error) {
	return c.trafficAggregate(ctx, from, to, func(t time.Time) time.Time {
		y, _, _ := t.UTC().Date()
		return time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC)
	})
}

func (c *Connections) Traffic(ctx context.Context, interval string, from, to time.Time) (contractconnection.TrafficSeries, error) {
	var (
		buckets []TrafficBucket
		err     error
	)
	switch interval {
	case "hour":
		buckets, err = c.TrafficHourly(ctx, from, to)
	case "day":
		buckets, err = c.TrafficDaily(ctx, from, to)
	case "month":
		buckets, err = c.TrafficMonthly(ctx, from, to)
	default:
		return contractconnection.TrafficSeries{}, fmt.Errorf("unsupported traffic interval %q", interval)
	}
	if err != nil {
		return contractconnection.TrafficSeries{}, err
	}

	items := make([]contractconnection.TrafficPoint, 0, len(buckets))
	for _, bucket := range buckets {
		items = append(items, contractconnection.TrafficPoint{
			Start:    bucket.StartUTC,
			Download: formatUint64(bucket.DownloadBytes),
			Upload:   formatUint64(bucket.UploadBytes),
		})
	}
	return contractconnection.TrafficSeries{Interval: interval, Items: items}, nil
}

func (c *Connections) Telemetry(ctx context.Context, from, to time.Time, limit int) (contractconnection.TelemetrySummary, error) {
	if c.sqliteDB == nil {
		return contractconnection.TelemetrySummary{}, errors.New("telemetry aggregation requires sqlite telemetry")
	}
	if limit <= 0 {
		limit = 8
	}

	dimensions := []string{"protocol", "inbound", "source", "addr", "outbound", "process", "rule", "tag", "destination"}
	groups := make([]contractconnection.TelemetryGroup, 0, len(dimensions))
	for _, dimension := range dimensions {
		items, err := c.telemetryDimension(ctx, dimension, from, to, limit)
		if err != nil {
			return contractconnection.TelemetrySummary{}, err
		}
		groups = append(groups, contractconnection.TelemetryGroup{Dimension: dimension, Items: items})
	}
	return contractconnection.TelemetrySummary{Groups: groups}, nil
}

func (c *Connections) telemetryDimension(ctx context.Context, dimension string, from, to time.Time, limit int) ([]contractconnection.TelemetryItem, error) {
	rows, err := c.sqliteDB.QueryContext(ctx, `
		SELECT value, download_bytes, upload_bytes, failed_count
		FROM (
			SELECT value, SUM(download_bytes) AS download_bytes,
				SUM(upload_bytes) AS upload_bytes, SUM(failed_count) AS failed_count
			FROM (
				SELECT v.value, t.download_bytes, t.upload_bytes, 0 AS failed_count
				FROM traffic_dimension_hourly t
				JOIN telemetry_dimension_values v ON v.id = t.value_id
				WHERE v.dimension = ? AND t.bucket_start_utc >= ? AND t.bucket_start_utc < ?

				UNION ALL

				SELECT v.value, d.download_bytes, d.upload_bytes, 0 AS failed_count
				FROM traffic_dimension_daily d
				JOIN telemetry_dimension_values v ON v.id = d.value_id
				WHERE v.dimension = ? AND d.bucket_start_utc < ? AND d.bucket_start_utc + 86400 > ?

				UNION ALL

				SELECT v.value, 0 AS download_bytes, 0 AS upload_bytes, f.failed_count
				FROM failure_dimension_hourly f
				JOIN telemetry_dimension_values v ON v.id = f.value_id
				WHERE v.dimension = ? AND f.bucket_start_utc >= ? AND f.bucket_start_utc < ?

				UNION ALL

				SELECT v.value, 0 AS download_bytes, 0 AS upload_bytes, d.failed_count
				FROM failure_dimension_daily d
				JOIN telemetry_dimension_values v ON v.id = d.value_id
				WHERE v.dimension = ? AND d.bucket_start_utc < ? AND d.bucket_start_utc + 86400 > ?
			)
			GROUP BY value
		)
		ORDER BY download_bytes + upload_bytes DESC, failed_count DESC
		LIMIT ?
	`, dimension, from.UTC().Unix(), to.UTC().Unix(),
		dimension, to.UTC().Unix(), from.UTC().Unix(),
		dimension, from.UTC().Unix(), to.UTC().Unix(),
		dimension, to.UTC().Unix(), from.UTC().Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]contractconnection.TelemetryItem, 0, limit)
	for rows.Next() {
		var value string
		var download, upload, failures uint64
		if err := rows.Scan(&value, &download, &upload, &failures); err != nil {
			return nil, err
		}
		items = append(items, contractconnection.TelemetryItem{
			Value:    value,
			Download: formatUint64(download),
			Upload:   formatUint64(upload),
			Failures: formatUint64(failures),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (c *Connections) trafficAggregate(ctx context.Context, from, to time.Time, truncate func(time.Time) time.Time) ([]TrafficBucket, error) {
	if c.sqliteDB == nil {
		return nil, errors.New("traffic aggregation requires sqlite telemetry")
	}

	rows, err := c.sqliteDB.QueryContext(ctx, `
		SELECT bucket_start_utc, upload_bytes, download_bytes
		FROM traffic_hourly
		WHERE bucket_start_utc >= ? AND bucket_start_utc < ?
		ORDER BY bucket_start_utc ASC
	`, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	buckets := map[int64]*TrafficBucket{}
	for rows.Next() {
		var start int64
		var upload, download uint64
		if err := rows.Scan(&start, &upload, &download); err != nil {
			return nil, err
		}

		group := truncate(time.Unix(start, 0).UTC()).Unix()
		bucket := buckets[group]
		if bucket == nil {
			bucket = &TrafficBucket{StartUTC: time.Unix(group, 0).UTC()}
			buckets[group] = bucket
		}
		bucket.UploadBytes += upload
		bucket.DownloadBytes += download
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := make([]TrafficBucket, 0, len(buckets))
	for _, bucket := range buckets {
		result = append(result, *bucket)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].StartUTC.Before(result[j].StartUTC)
	})

	return result, nil
}
