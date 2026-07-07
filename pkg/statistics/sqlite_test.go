package statistics

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cache/memory"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/protos/tools"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestSQLiteTelemetryPersistsTotalsAndHistory(t *testing.T) {
	t.Parallel()

	path := tools.PathGenerator.State(t.TempDir())

	cache := NewSQLiteTotalCache(path)
	cache.AddDownload(123)
	cache.AddUpload(456)
	cache.Close()

	history := NewSQLiteHistory(path)
	history.Push(statistic.Connection_builder{
		Id:      new(uint64(1)),
		Addr:    new("example.com:443"),
		Process: new("curl"),
		Type: statistic.NetType_builder{
			ConnType: statistic.Type_tcp.Enum(),
		}.Build(),
	}.Build())

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
	if len(resp.GetObjects()) != 1 {
		t.Fatalf("expected 1 history object, got %d", len(resp.GetObjects()))
	}
	if got := resp.GetObjects()[0].GetConnection().GetAddr(); got != "example.com:443" {
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
}

func TestSQLiteTotalCacheImportsLegacyFlowData(t *testing.T) {
	t.Parallel()

	path := tools.PathGenerator.State(t.TempDir())
	legacy := memory.NewMemoryCache().NewCache("flow_data")
	if err := legacy.Put(legacyDownloadKey, binary.BigEndian.AppendUint64(nil, 987)); err != nil {
		t.Fatalf("seed legacy download failed: %v", err)
	}
	if err := legacy.Put(legacyUploadKey, binary.BigEndian.AppendUint64(nil, 654)); err != nil {
		t.Fatalf("seed legacy upload failed: %v", err)
	}

	cache := NewSQLiteTotalCache(path, legacy)
	defer cache.Close()

	if cache.LoadDownload() != 987 || cache.LoadUpload() != 654 {
		t.Fatalf("unexpected imported totals download=%d upload=%d", cache.LoadDownload(), cache.LoadUpload())
	}

	store, err := storagesqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	defer store.Close()

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
