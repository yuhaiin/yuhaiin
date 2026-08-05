package statistics

import (
	"context"
	"database/sql"
	"encoding/binary"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cache/memory"
	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	legacymigrate "github.com/Asutorufa/yuhaiin/pkg/legacy/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestSQLiteTelemetryPersistsTotalsAndHistory(t *testing.T) {
	t.Parallel()

	path := paths.PathGenerator.State(t.TempDir())

	cache := NewSQLiteTotalCache(path)
	cache.AddDownload(123)
	cache.AddUpload(456)
	cache.Close()

	history := NewSQLiteHistory(path)
	history.Push(contractconnection.Connection{
		ID:      "1",
		Addr:    "example.com:443",
		Process: "curl",
		Network: contractconnection.NetworkType{
			ConnType: "tcp",
		},
	})

	store, err := storagesqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	defer store.Close()

	var download, upload uint64
	if err := store.DB().QueryRowContext(context.Background(), `
		SELECT value_int FROM statistics_kv WHERE key = 'total_download'
	`).Scan(&download); err != nil {
		t.Fatalf("query total_download failed: %v", err)
	}
	if err := store.DB().QueryRowContext(context.Background(), `
		SELECT value_int FROM statistics_kv WHERE key = 'total_upload'
	`).Scan(&upload); err != nil {
		t.Fatalf("query total_upload failed: %v", err)
	}
	if download != 123 || upload != 456 {
		t.Fatalf("unexpected totals download=%d upload=%d", download, upload)
	}

	var hourlyDownload, hourlyUpload uint64
	if err := store.DB().QueryRowContext(context.Background(), `
		SELECT download_bytes, upload_bytes FROM traffic_hourly LIMIT 1
	`).Scan(&hourlyDownload, &hourlyUpload); err != nil {
		t.Fatalf("query traffic_hourly failed: %v", err)
	}
	if hourlyDownload != 123 || hourlyUpload != 456 {
		t.Fatalf("unexpected hourly download=%d upload=%d", hourlyDownload, hourlyUpload)
	}

	resp := history.Get()
	if len(resp.Items) != 1 {
		t.Fatalf("expected 1 history object, got %d", len(resp.Items))
	}
	if got := resp.Items[0].Connection.Addr; got != "example.com:443" {
		t.Fatalf("expected history addr example.com:443, got %q", got)
	}

	connections := NewSQLiteConnStore(path, nil)
	defer connections.Close()

	daily, err := connections.TrafficDaily(context.Background(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("query daily traffic failed: %v", err)
	}
	if len(daily) != 1 {
		t.Fatalf("expected 1 daily bucket, got %d", len(daily))
	}
	if daily[0].DownloadBytes != 123 || daily[0].UploadBytes != 456 {
		t.Fatalf("unexpected daily traffic download=%d upload=%d", daily[0].DownloadBytes, daily[0].UploadBytes)
	}

	series, err := connections.Traffic(context.Background(), "day", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("query traffic series failed: %v", err)
	}
	if series.Interval != "day" || len(series.Items) != 1 || series.Items[0].Download != "123" || series.Items[0].Upload != "456" {
		t.Fatalf("unexpected traffic series: %+v", series)
	}
}

func TestTelemetryDimensionsAggregateTrafficAndFailures(t *testing.T) {
	ctx := context.Background()
	connections := NewSQLiteConnStore(paths.PathGenerator.State(t.TempDir()), nil)
	defer connections.Close()

	info := contractconnection.Connection{
		Addr:     "example.com:443",
		Domain:   "example.com",
		Inbound:  "socks5",
		Source:   "127.0.0.1:52001",
		NodeName: "edge-a",
		Process:  "curl",
		Tag:      "streaming",
		Network:  contractconnection.NetworkType{ConnType: "tcp"},
		MatchHistory: []contractconnection.MatchHistoryEntry{{
			RuleName: "media-rule",
		}},
	}
	counter := connections.telemetry.Register(info)
	counter.download.Add(123)
	counter.upload.Add(456)
	connections.telemetry.Remove(counter)
	connections.telemetry.flush()
	connections.telemetry.RecordFailure(info)

	summary, err := connections.Telemetry(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 8)
	if err != nil {
		t.Fatalf("query telemetry summary failed: %v", err)
	}
	groups := make(map[string]contractconnection.TelemetryItem, len(summary.Groups))
	for _, group := range summary.Groups {
		if len(group.Items) > 0 {
			groups[group.Dimension] = group.Items[0]
		}
	}
	for dimension, value := range map[string]string{
		"protocol": "tcp", "inbound": "socks5", "source": "127.0.0.1", "addr": "example.com:443", "outbound": "edge-a", "process": "curl", "rule": "media-rule", "tag": "streaming", "destination": "example.com",
	} {
		item, ok := groups[dimension]
		if !ok || item.Value != value || item.Download != "123" || item.Upload != "456" || item.Failures != "1" {
			t.Fatalf("unexpected %s telemetry item: %+v", dimension, item)
		}
	}
}

func TestTelemetryDimensionReturnsSQLSortedTopValues(t *testing.T) {
	ctx := context.Background()
	connections := NewSQLiteConnStore(paths.PathGenerator.State(t.TempDir()), nil)
	defer connections.Close()

	bucket := time.Now().UTC().Truncate(time.Hour).Unix()
	for _, entry := range []struct {
		value    string
		download uint64
		upload   uint64
	}{
		{value: "alpha", download: 10},
		{value: "bravo", download: 100},
		{value: "tie-low-failures", download: 50},
		{value: "tie-high-failures", download: 50},
	} {
		valueID := seedTelemetryValue(t, ctx, connections.sqliteDB, "protocol", entry.value)
		if _, err := connections.sqliteDB.ExecContext(ctx, `
			INSERT INTO traffic_dimension_hourly(bucket_start_utc, value_id, upload_bytes, download_bytes)
			VALUES (?, ?, ?, ?)
		`, bucket, valueID, entry.upload, entry.download); err != nil {
			t.Fatalf("seed traffic telemetry: %v", err)
		}
	}
	for _, entry := range []struct {
		value    string
		failures uint64
	}{
		{value: "tie-high-failures", failures: 3},
		{value: "failure-only", failures: 9},
	} {
		valueID := seedTelemetryValue(t, ctx, connections.sqliteDB, "protocol", entry.value)
		if _, err := connections.sqliteDB.ExecContext(ctx, `
			INSERT INTO failure_dimension_hourly(bucket_start_utc, value_id, failed_count)
			VALUES (?, ?, ?)
		`, bucket, valueID, entry.failures); err != nil {
			t.Fatalf("seed failure telemetry: %v", err)
		}
	}

	items, err := connections.telemetryDimension(ctx, "protocol", time.Unix(bucket-1, 0), time.Unix(bucket+1, 0), 3)
	if err != nil {
		t.Fatalf("query telemetry dimension: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("expected 3 telemetry items, got %d: %+v", len(items), items)
	}
	for i, want := range []string{"bravo", "tie-high-failures", "tie-low-failures"} {
		if items[i].Value != want {
			t.Fatalf("unexpected item %d: got %+v, want value %q", i, items[i], want)
		}
	}
	if items[1].Failures != "3" {
		t.Fatalf("unexpected failure count: %+v", items[1])
	}

	items, err = connections.telemetryDimension(ctx, "protocol", time.Unix(bucket-1, 0), time.Unix(bucket+1, 0), 5)
	if err != nil {
		t.Fatalf("query telemetry dimension including failure-only value: %v", err)
	}
	if got := items[len(items)-1]; got.Value != "failure-only" || got.Failures != "9" {
		t.Fatalf("failure-only telemetry value missing: %+v", items)
	}
}

func seedTelemetryValue(t *testing.T, ctx context.Context, db *sql.DB, dimension, value string) int64 {
	t.Helper()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO telemetry_dimension_values(dimension, value)
		VALUES (?, ?)
		ON CONFLICT(dimension, value) DO NOTHING
	`, dimension, value); err != nil {
		t.Fatalf("seed telemetry value: %v", err)
	}
	var id int64
	if err := db.QueryRowContext(ctx, `
		SELECT id FROM telemetry_dimension_values WHERE dimension = ? AND value = ?
	`, dimension, value).Scan(&id); err != nil {
		t.Fatalf("load telemetry value id: %v", err)
	}
	return id
}

func TestNormalizeTelemetrySource(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
	}{
		{input: "http2.h-20-2127.0.0.1:52001", want: "127.0.0.1"},
		{input: "http2.h-20-2example.com:443", want: "example.com"},
		{input: "http2.h-20-2[2407:cdc0:8205:26cd:6812:56e0:3052:8cd3]:55391", want: "2407:cdc0:8205:26cd:6812:56e0:3052:8cd3"},
		{input: "[::1]:443", want: "::1"},
		{input: "2407:cdc0::1", want: "2407:cdc0::1"},
	} {
		if got := normalizeTelemetrySource(test.input); got != test.want {
			t.Errorf("normalizeTelemetrySource(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestTelemetryDimensionsSkipFakeIPDestination(t *testing.T) {
	info := contractconnection.Connection{
		Addr:        "10.0.0.1:443",
		Destination: "10.0.0.1:443",
		FakeIP:      "10.0.0.1:443",
		Domain:      "example.com:443",
	}
	values := dimensionsForConnection(info)
	for _, value := range values {
		if value.kind == "destination" {
			t.Fatalf("fakeip destination should be omitted: %+v", values)
		}
	}
	for _, value := range values {
		if value.kind == "addr" && value.value != "example.com:443" {
			t.Fatalf("fakeip addr = %q, want real domain", value.value)
		}
	}
}

func TestNormalizePersistedFakeIPDestinations(t *testing.T) {
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, paths.PathGenerator.State(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO fakeip_entries(family, prefix, domain, ip, created_at, last_used_at)
		VALUES (4, '10.0.0.0/24', 'example.com', ?, 1, 2)
	`, []byte{10, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}
	valueID := seedTelemetryValue(t, ctx, store.DB(), "destination", "10.0.0.1:443")
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO traffic_dimension_hourly(bucket_start_utc, value_id, download_bytes)
		VALUES (1, ?, 7)
	`, valueID); err != nil {
		t.Fatal(err)
	}

	normalizePersistedFakeIPDestinations(store.DB())
	var remaining int
	if err := store.DB().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM traffic_dimension_hourly h
		JOIN telemetry_dimension_values v ON v.id = h.value_id
		WHERE v.dimension = 'destination'
	`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("fakeip destination rows remaining = %d, want 0", remaining)
	}
}

func TestTelemetryMaintenanceRollsHourlyIntoDaily(t *testing.T) {
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, paths.PathGenerator.State(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	valueID := seedTelemetryValue(t, ctx, store.DB(), "protocol", "tcp")
	oldBucket := time.Now().UTC().Truncate(time.Hour).Add(-telemetryHourlyRetention - time.Hour).Unix()
	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO traffic_dimension_hourly(bucket_start_utc, value_id, download_bytes)
		VALUES (?, ?, 11)
	`, oldBucket, valueID); err != nil {
		t.Fatal(err)
	}

	recorder := &telemetryRecorder{db: store.DB()}
	recorder.compactOldTelemetry(time.Now())

	var daily int64
	if err := store.DB().QueryRowContext(ctx, `
		SELECT download_bytes FROM traffic_dimension_daily WHERE value_id = ?
	`, valueID).Scan(&daily); err != nil {
		t.Fatal(err)
	}
	if daily != 11 {
		t.Fatalf("daily telemetry download = %d, want 11", daily)
	}
}

func TestSQLiteTotalCacheImportsLegacyFlowData(t *testing.T) {
	t.Parallel()

	path := paths.PathGenerator.State(t.TempDir())
	legacy := memory.NewMemoryCache().NewCache("flow_data")
	if err := legacy.Put([]byte("DOWNLOAD"), binary.BigEndian.AppendUint64(nil, 987)); err != nil {
		t.Fatalf("seed legacy download failed: %v", err)
	}
	if err := legacy.Put([]byte("UPLOAD"), binary.BigEndian.AppendUint64(nil, 654)); err != nil {
		t.Fatalf("seed legacy upload failed: %v", err)
	}

	store, err := storagesqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	defer store.Close()
	if err := legacymigrate.MigrateLegacyTotalFlow(context.Background(), store.DB(), legacy); err != nil {
		t.Fatalf("import legacy total flow failed: %v", err)
	}

	cache := NewSQLiteTotalCache(path)
	defer cache.Close()

	if cache.LoadDownload() != 987 || cache.LoadUpload() != 654 {
		t.Fatalf("unexpected imported totals download=%d upload=%d", cache.LoadDownload(), cache.LoadUpload())
	}

	var source string
	if err := store.DB().QueryRowContext(context.Background(), `
		SELECT value FROM metadata WHERE key = 'legacy_total_flow_import_source'
	`).Scan(&source); err != nil {
		t.Fatalf("query import metadata failed: %v", err)
	}
	if source != "pebble_flow_data" {
		t.Fatalf("unexpected import source %q", source)
	}
}

func TestSQLiteConnectionSessionsAreRuntimeOnly(t *testing.T) {
	ctx := context.Background()
	path := paths.PathGenerator.State(t.TempDir())
	store, err := storagesqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}

	infoStore := newSQLiteInfoStore(store.DB())
	infoStore.Store(1, contractconnection.Connection{
		ID:   "1",
		Addr: "example.com:443",
		Network: contractconnection.NetworkType{
			ConnType: "tcp",
		},
	})
	infoStore.Delete(1)
	assertConnectionSessionCount(t, ctx, store.DB(), 0)

	if _, err := store.DB().ExecContext(ctx, `
		INSERT INTO connection_sessions(id, opened_at, last_seen_at, state, protocol, summary_json)
		VALUES (2, 1, 1, 'closed', 'tcp', '{}'), (3, 1, 1, 'open', 'tcp', '{}')
	`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	connections := NewSQLiteConnStore(path, nil)
	if err := connections.Close(); err != nil {
		t.Fatal(err)
	}

	check, err := storagesqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	assertConnectionSessionCount(t, ctx, check.DB(), 0)
}

func assertConnectionSessionCount(t *testing.T, ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, want int) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM connection_sessions`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("connection session count = %d, want %d", got, want)
	}
}
