package statistics

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"sort"
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

type sqliteInfoStore struct {
	db *sql.DB
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
	return &sqliteInfoStore{db: db}
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
	data, err := encodeStatisticJSON(info)
	if err != nil {
		log.Warn("encode sqlite connection session failed", "id", id, "err", err)
		return
	}

	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx, `
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
	`, id, now, now, info.Network.ConnType, info.Process, info.Inbound,
		info.InboundName, info.Outbound, info.Network.ConnType,
		info.Destination, info.Addr, data); err != nil {
		log.Warn("store sqlite connection session failed", "id", id, "err", err)
	}
}

func (s *sqliteInfoStore) Delete(id uint64) {
	if s.db == nil {
		return
	}

	if _, err := s.db.ExecContext(context.Background(), `DELETE FROM connection_sessions WHERE id = ?`, id); err != nil {
		log.Warn("delete sqlite connection session failed", "id", id, "err", err)
	}
}

func (*sqliteInfoStore) Close() error { return nil }

type SQLiteHistory struct {
	db      *sql.DB
	closeDB func() error
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
	return &SQLiteHistory{db: db}
}

func newSQLiteHistoryWithClose(db *sql.DB, closeDB func() error) *SQLiteHistory {
	return &SQLiteHistory{db: db, closeDB: closeDB}
}

func (h *SQLiteHistory) Push(c contractconnection.Connection) {
	if h.db == nil {
		return
	}

	ctx := context.Background()
	data, err := encodeStatisticJSON(c)
	if err != nil {
		log.Warn("encode sqlite history failed", "err", err)
		return
	}

	now := time.Now().Unix()
	if _, err := h.db.ExecContext(ctx, `
		INSERT INTO connection_history(protocol, addr, process_name, hit_count, last_seen_at, last_connection_json)
		VALUES (?, ?, ?, 1, ?, ?)
		ON CONFLICT(protocol, addr, process_name) DO UPDATE SET
			hit_count = hit_count + 1,
			last_seen_at = excluded.last_seen_at,
			last_connection_json = excluded.last_connection_json
	`, c.Network.ConnType, c.Addr, c.Process, now, data); err != nil {
		log.Warn("store sqlite history failed", "err", err)
	}
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
	if h.closeDB == nil {
		return nil
	}
	return h.closeDB()
}

type SQLiteFailedHistory struct {
	db      *sql.DB
	closeDB func() error
}

func NewSQLiteFailedHistory(path string) *SQLiteFailedHistory {
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, path)
	if err != nil {
		log.Warn("open sqlite failed history failed", "err", err)
		return newSQLiteFailedHistory(nil)
	}
	return &SQLiteFailedHistory{db: store.DB(), closeDB: store.Close}
}

func newSQLiteFailedHistory(db *sql.DB) *SQLiteFailedHistory {
	return &SQLiteFailedHistory{db: db}
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

	now := time.Now().Unix()
	if _, execErr := h.db.ExecContext(context.Background(), `
		INSERT INTO failed_connection_history(protocol, host, process_name, failed_count, last_seen_at, last_error)
		VALUES (?, ?, ?, 1, ?, ?)
		ON CONFLICT(protocol, host, process_name) DO UPDATE SET
			failed_count = failed_count + 1,
			last_seen_at = excluded.last_seen_at,
			last_error = excluded.last_error
	`, protocol, getRealAddr(storeContext, host), storeContext.GetProcessName(), now, err.Error()); execErr != nil {
		log.Warn("store sqlite failed history failed", "err", execErr)
	}
}

func (h *SQLiteFailedHistory) Get() contractconnection.FailedHistoryList {
	if h.db == nil {
		return contractconnection.FailedHistoryList{}
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
	if h.closeDB == nil {
		return nil
	}
	return h.closeDB()
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
