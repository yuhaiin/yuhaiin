package statistics

import (
	"context"
	"encoding/binary"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/log"
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

	cancel           context.CancelFunc
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

func NewTotalCache(cc cache.Cache) *TotalCache {
	ctx, cancel := context.WithCancel(context.Background())
	c := &TotalCache{
		cache:           cc,
		ctx:             ctx,
		cancel:          cancel,
		triggerDownload: make(chan struct{}),
		triggerUpload:   make(chan struct{}),
	}

	if download, _ := cc.Get(DownloadKey); len(download) >= 8 {
		c.lastDownload.Store(binary.BigEndian.Uint64(download))
	}

	if upload, _ := cc.Get(UploadKey); len(upload) >= 8 {
		c.lastUpload.Store(binary.BigEndian.Uint64(upload))
	}

	log.Info("get total cache", slog.Any("download", c.lastDownload.Load()), slog.Any("upload", c.lastUpload.Load()))

	c.wg.Go(func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-c.triggerDownload:
				notSyncDownload := c.notSyncDownload.Load()
				_ = c.cache.Put(DownloadKey, binary.BigEndian.AppendUint64(nil, c.lastDownload.Load()+c.download.Add(uint64(c.notSyncDownload.Load()))))
				c.notSyncDownload.Add(-notSyncDownload)
				c.triggerdDownload.Store(false)

			case <-c.triggerUpload:
				notSyncUpload := c.notSyncUpload.Load()
				_ = c.cache.Put(UploadKey, binary.BigEndian.AppendUint64(nil, c.lastUpload.Load()+c.upload.Add(uint64(c.notSyncUpload.Load()))))
				c.notSyncUpload.Add(-notSyncUpload)
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
	c.cache.Batch(func(txn cache.Batch) error {
		err := txn.Put(DownloadKey, binary.BigEndian.AppendUint64(nil, c.lastDownload.Load()+c.download.Add(uint64(c.notSyncDownload.Load()))))
		if err != nil {
			return err
		}
		return txn.Put(UploadKey, binary.BigEndian.AppendUint64(nil, c.lastUpload.Load()+c.upload.Add(uint64(c.notSyncUpload.Load()))))
	})
}
