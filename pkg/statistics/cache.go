package statistics

import (
	"context"
	"encoding/binary"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
)

var (
	DownloadKey = []byte{'D', 'O', 'W', 'N', 'L', 'O', 'A', 'D'}
	UploadKey   = []byte{'U', 'P', 'L', 'O', 'A', 'D'}

	SyncThreshold int64 = 1024 * 1024 * 50 // bytes
)

type TotalCache struct {
	cache cache.Cache
	ctx   context.Context

	// trigger to sync to disk
	triggerDownload chan struct{}
	triggerUpload   chan struct{}

	cancel   context.CancelFunc
	wg       sync.WaitGroup
	download atomic.Uint64
	upload   atomic.Uint64

	notSyncDownload  atomic.Int64
	notSyncUpload    atomic.Int64
	triggerdDownload atomic.Bool
	triggerdUpload   atomic.Bool
}

func NewTotalCache(cache cache.Cache) *TotalCache {
	ctx, cancel := context.WithCancel(context.Background())
	c := &TotalCache{
		cache:           cache,
		ctx:             ctx,
		cancel:          cancel,
		triggerDownload: make(chan struct{}),
		triggerUpload:   make(chan struct{}),
	}

	if download := cache.Get(DownloadKey); len(download) >= 8 {
		c.download.Store(binary.BigEndian.Uint64(download))
	}

	if upload := cache.Get(UploadKey); len(upload) >= 8 {
		c.upload.Store(binary.BigEndian.Uint64(upload))
	}

	slog.Info("get total cache", slog.Any("download", c.download.Load()), slog.Any("upload", c.upload.Load()))

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-c.triggerDownload:
				notSyncDownload := c.notSyncDownload.Load()
				c.cache.Put(DownloadKey, binary.BigEndian.AppendUint64(nil, c.download.Add(uint64(notSyncDownload))))
				c.notSyncDownload.Add(-notSyncDownload)
				c.triggerdDownload.Store(false)

			case <-c.triggerUpload:
				notSyncUpload := c.notSyncUpload.Load()
				c.cache.Put(UploadKey, binary.BigEndian.AppendUint64(nil, c.upload.Add(uint64(notSyncUpload))))
				c.notSyncUpload.Add(-notSyncUpload)
				c.triggerdUpload.Store(false)
			}
		}
	}()

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
	metrics.Counter.AddDownload(int(d))
	z := c.notSyncDownload.Add(int64(d))
	c.trigger(z, c.triggerDownload, &c.triggerdDownload)
}

func (c *TotalCache) LoadDownload() uint64 {
	return c.download.Load() + uint64(c.notSyncDownload.Load())
}

func (c *TotalCache) AddUpload(d uint64) {
	metrics.Counter.AddUpload(int(d))
	z := c.notSyncUpload.Add(int64(d))
	c.trigger(z, c.triggerUpload, &c.triggerdUpload)
}

func (c *TotalCache) LoadUpload() uint64 { return c.upload.Load() + uint64(c.notSyncUpload.Load()) }

func (c *TotalCache) Close() {
	c.cancel()
	c.wg.Wait()
	c.cache.Put(DownloadKey, binary.BigEndian.AppendUint64(nil, c.download.Add(uint64(c.notSyncDownload.Load()))))
	c.cache.Put(UploadKey, binary.BigEndian.AppendUint64(nil, c.upload.Add(uint64(c.notSyncUpload.Load()))))
}
