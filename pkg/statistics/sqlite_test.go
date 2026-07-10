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
