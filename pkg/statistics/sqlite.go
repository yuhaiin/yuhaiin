package statistics

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"sort"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/api"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type TrafficBucket struct {
	StartUTC      time.Time
	UploadBytes   uint64
	DownloadBytes uint64
}

type sqliteInfoStore struct {
	db *sql.DB
}

func markInterruptedSessions(db *sql.DB) {
	if db == nil {
		return
	}

	ctx := context.Background()
	now := time.Now().Unix()
	if _, err := db.ExecContext(ctx, `
		UPDATE connection_sessions
		SET state = 'interrupted', closed_at = ?, last_seen_at = ?
		WHERE state = 'open'
	`, now, now); err != nil {
		log.Warn("mark interrupted sessions failed", "err", err)
	}
}

func newSQLiteInfoStore(db *sql.DB) *sqliteInfoStore {
	return &sqliteInfoStore{db: db}
}

func (s *sqliteInfoStore) Load(id uint64) (*statistic.Connection, bool) {
	if s.db == nil {
		return nil, false
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
		return nil, false
	}

	info := &statistic.Connection{}
	if err := decodeStatisticJSON(data, info); err != nil {
		log.Warn("decode sqlite connection session failed", "id", id, "err", err)
		return nil, false
	}
	return info, true
}

func (s *sqliteInfoStore) Store(id uint64, info *statistic.Connection) {
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
	`, id, now, now, int(info.GetType().GetConnType()), info.GetProcess(), info.GetInbound(),
		info.GetInboundName(), info.GetOutbound(), info.GetType().GetConnType().String(),
		info.GetDestionation(), info.GetAddr(), data); err != nil {
		log.Warn("store sqlite connection session failed", "id", id, "err", err)
	}
}

func (s *sqliteInfoStore) Delete(id uint64) {
	if s.db == nil {
		return
	}

	ctx := context.Background()
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx, `
		UPDATE connection_sessions
		SET state = 'closed', closed_at = ?, last_seen_at = ?
		WHERE id = ?
	`, now, now, id); err != nil {
		log.Warn("close sqlite connection session failed", "id", id, "err", err)
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

func (h *SQLiteHistory) Push(c *statistic.Connection) {
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
	`, int(c.GetType().GetConnType()), c.GetAddr(), c.GetProcess(), now, data); err != nil {
		log.Warn("store sqlite history failed", "err", err)
	}
}

func (h *SQLiteHistory) Get() *api.AllHistoryList {
	if h.db == nil {
		return &api.AllHistoryList{}
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
		return &api.AllHistoryList{}
	}
	defer rows.Close()

	var objects []*api.AllHistory
	dumpProcess := false
	for rows.Next() {
		var count uint64
		var lastSeen int64
		var data string
		if err := rows.Scan(&count, &lastSeen, &data); err != nil {
			log.Warn("scan sqlite history failed", "err", err)
			continue
		}

		info := &statistic.Connection{}
		if err := decodeStatisticJSON(data, info); err != nil {
			log.Warn("decode sqlite history failed", "err", err)
			continue
		}
		if !dumpProcess && info.GetProcess() != "" {
			dumpProcess = true
		}
		objects = append(objects, api.AllHistory_builder{
			Count:      new(count),
			Time:       timestamppb.New(time.Unix(lastSeen, 0)),
			Connection: info,
		}.Build())
	}

	return api.AllHistoryList_builder{
		Objects:            objects,
		DumpProcessEnabled: new(dumpProcess),
	}.Build()
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

func (h *SQLiteFailedHistory) Push(ctx context.Context, err error, protocol statistic.Type, host netapi.Address) {
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
	`, int(protocol), getRealAddr(storeContext, host), storeContext.GetProcessName(), now, err.Error()); execErr != nil {
		log.Warn("store sqlite failed history failed", "err", execErr)
	}
}

func (h *SQLiteFailedHistory) Get() *api.FailedHistoryList {
	if h.db == nil {
		return &api.FailedHistoryList{}
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
		return &api.FailedHistoryList{}
	}
	defer rows.Close()

	var objects []*api.FailedHistory
	dumpProcess := false
	for rows.Next() {
		var protocol int
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
		objects = append(objects, api.FailedHistory_builder{
			Protocol:    statistic.Type(protocol).Enum(),
			Host:        new(host),
			Error:       new(lastError),
			Process:     new(process),
			Time:        timestamppb.New(time.Unix(lastSeen, 0)),
			FailedCount: new(failedCount),
		}.Build())
	}

	return api.FailedHistoryList_builder{
		Objects:            objects,
		DumpProcessEnabled: new(dumpProcess),
	}.Build()
}

func (h *SQLiteFailedHistory) Close() error {
	if h.closeDB == nil {
		return nil
	}
	return h.closeDB()
}

func encodeStatisticJSON(msg proto.Message) (string, error) {
	data, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(msg)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeStatisticJSON(data string, msg proto.Message) error {
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal([]byte(data), msg)
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
