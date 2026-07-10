package statistics

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

var (
	SyncThreshold int64 = 1024 * 1024 * 50 // bytes
)

type TotalCache struct {
	ctx context.Context

	// trigger to sync to disk
	triggerDownload chan struct{}
	triggerUpload   chan struct{}

	cancel           context.CancelFunc
	sqliteDB         *sql.DB
	closeDB          func() error
	wg               sync.WaitGroup
	lastDownload     atomic.Uint64
	lastUpload       atomic.Uint64
	download         atomic.Uint64
	upload           atomic.Uint64
	notSyncDownload  atomic.Int64
	notSyncUpload    atomic.Int64
	triggerdDownload atomic.Bool
	triggerdUpload   atomic.Bool
}

func NewSQLiteTotalCache(path string) *TotalCache {
	ctx := context.Background()
	store, err := storagesqlite.Open(ctx, path)
	if err != nil {
		log.Warn("open sqlite total cache failed", "err", err)
		return newSQLiteTotalCache(nil, nil)
	}

	return newSQLiteTotalCache(store.DB(), store.Close)
}

func newSQLiteTotalCache(db *sql.DB, closeDB func() error) *TotalCache {
	ctx, cancel := context.WithCancel(context.Background())
	c := &TotalCache{
		ctx:              ctx,
		cancel:           cancel,
		sqliteDB:         db,
		closeDB:          closeDB,
		triggerDownload:  make(chan struct{}),
		triggerUpload:    make(chan struct{}),
		triggerdDownload: atomic.Bool{},
		triggerdUpload:   atomic.Bool{},
	}

	if db != nil {
		download, upload, err := loadSQLiteTotal(ctx, db)
		if err != nil {
			log.Warn("load sqlite total flow failed", "err", err)
		}
		c.lastDownload.Store(download)
		c.lastUpload.Store(upload)
	}

	log.Info("get sqlite total cache", slog.Any("download", c.lastDownload.Load()), slog.Any("upload", c.lastUpload.Load()))

	c.wg.Go(func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-c.triggerDownload:
				delta := c.notSyncDownload.Load()
				totalDownload := c.lastDownload.Load() + c.download.Add(uint64(delta))
				if err := persistSQLiteTotal(c.ctx, c.sqliteDB, uint64(delta), 0, totalDownload, c.LoadUpload()); err != nil {
					log.Warn("persist sqlite download total failed", "err", err)
				}
				c.notSyncDownload.Add(-delta)
				c.triggerdDownload.Store(false)
			case <-c.triggerUpload:
				delta := c.notSyncUpload.Load()
				totalUpload := c.lastUpload.Load() + c.upload.Add(uint64(delta))
				if err := persistSQLiteTotal(c.ctx, c.sqliteDB, 0, uint64(delta), c.LoadDownload(), totalUpload); err != nil {
					log.Warn("persist sqlite upload total failed", "err", err)
				}
				c.notSyncUpload.Add(-delta)
				c.triggerdUpload.Store(false)
			}
		}
	})

	return c
}

func (c *TotalCache) trigger(z int64, ch chan struct{}, atomic *atomic.Bool) {
	if z >= SyncThreshold && !atomic.Load() {
		select {
		case ch <- struct{}{}:
			atomic.Store(true)
		case <-c.ctx.Done():
		default:
		}
	}
}

func (c *TotalCache) AddDownload(d uint64) {
	z := c.notSyncDownload.Add(int64(d))
	c.trigger(z, c.triggerDownload, &c.triggerdDownload)
}

func (c *TotalCache) LoadDownload() uint64 {
	return c.lastDownload.Load() + c.download.Load() + uint64(c.notSyncDownload.Load())
}

func (c *TotalCache) LoadRunningDownload() uint64 {
	return c.download.Load() + uint64(c.notSyncDownload.Load())
}

func (c *TotalCache) AddUpload(d uint64) {
	z := c.notSyncUpload.Add(int64(d))
	c.trigger(z, c.triggerUpload, &c.triggerdUpload)
}

func (c *TotalCache) LoadUpload() uint64 {
	return c.lastUpload.Load() + c.upload.Load() + uint64(c.notSyncUpload.Load())
}

func (c *TotalCache) LoadRunningUpload() uint64 {
	return c.upload.Load() + uint64(c.notSyncUpload.Load())
}

func (c *TotalCache) Close() {
	c.cancel()
	c.wg.Wait()
	downloadDelta := uint64(c.notSyncDownload.Load())
	uploadDelta := uint64(c.notSyncUpload.Load())
	totalDownload := c.lastDownload.Load() + c.download.Add(downloadDelta)
	totalUpload := c.lastUpload.Load() + c.upload.Add(uploadDelta)
	if err := persistSQLiteTotal(context.Background(), c.sqliteDB, downloadDelta, uploadDelta, totalDownload, totalUpload); err != nil {
		log.Warn("close sqlite total cache failed", "err", err)
	}
	if c.closeDB != nil {
		if err := c.closeDB(); err != nil {
			log.Warn("close sqlite total cache db failed", "err", err)
		}
	}
}

func loadSQLiteTotal(ctx context.Context, db *sql.DB) (download uint64, upload uint64, err error) {
	if db == nil {
		return 0, 0, nil
	}

	load := func(key string) (uint64, error) {
		var value uint64
		err := db.QueryRowContext(ctx, `
			SELECT value_int
			FROM statistics_kv
			WHERE key = ?
		`, key).Scan(&value)
		switch {
		case err == nil:
			return value, nil
		case err == sql.ErrNoRows:
			return 0, nil
		default:
			return 0, err
		}
	}

	download, err = load("total_download")
	if err != nil {
		return 0, 0, fmt.Errorf("load total_download failed: %w", err)
	}
	upload, err = load("total_upload")
	if err != nil {
		return 0, 0, fmt.Errorf("load total_upload failed: %w", err)
	}
	return download, upload, nil
}

func persistSQLiteTotal(ctx context.Context, db *sql.DB, downloadDelta, uploadDelta, totalDownload, totalUpload uint64) error {
	if db == nil {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().Unix()
	for key, value := range map[string]uint64{
		"total_download": totalDownload,
		"total_upload":   totalUpload,
	} {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO statistics_kv(key, value_int, updated_at)
			VALUES (?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET
				value_int = excluded.value_int,
				updated_at = excluded.updated_at
		`, key, value, now); err != nil {
			return err
		}
	}

	if downloadDelta != 0 || uploadDelta != 0 {
		bucket := time.Now().UTC().Truncate(time.Hour).Unix()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO traffic_hourly(bucket_start_utc, upload_bytes, download_bytes, updated_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(bucket_start_utc) DO UPDATE SET
				upload_bytes = upload_bytes + excluded.upload_bytes,
				download_bytes = download_bytes + excluded.download_bytes,
				updated_at = excluded.updated_at
		`, bucket, uploadDelta, downloadDelta, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}
