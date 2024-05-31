package statistics

import (
	"encoding/binary"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
)

var (
	DownloadKey = []byte{'D', 'O', 'W', 'N', 'L', 'O', 'A', 'D'}
	UploadKey   = []byte{'U', 'P', 'L', 'O', 'A', 'D'}

	SyncThreshold int64 = 1024 * 1024 * 50 // bytes
)

type TotalCache struct {
	download atomic.Uint64
	upload   atomic.Uint64

	notSyncDownload atomic.Int64
	notSyncUpload   atomic.Int64
	syncingDownload atomic.Bool
	syncingUpload   atomic.Bool

	cache *cache.Cache
}

func NewTotalCache(cache *cache.Cache) *TotalCache {
	c := &TotalCache{
		cache: cache,
	}

	if download := cache.Get(DownloadKey); len(download) >= 8 {
		c.download.Store(binary.BigEndian.Uint64(download))
	}

	if upload := cache.Get(UploadKey); len(upload) >= 8 {
		c.upload.Store(binary.BigEndian.Uint64(upload))
	}

	return c
}

func (c *TotalCache) AddDownload(d uint64) {
	z := c.notSyncDownload.Add(int64(d))
	if z >= SyncThreshold && c.syncingDownload.CompareAndSwap(false, true) {
		c.cache.Put(DownloadKey, binary.BigEndian.AppendUint64(nil, c.download.Add(uint64(z))))
		c.notSyncDownload.Add(-z)
		c.syncingDownload.Store(false)
	}
}

func (c *TotalCache) LoadDownload() uint64 {
	return c.download.Load() + uint64(c.notSyncDownload.Load())
}

func (c *TotalCache) AddUpload(d uint64) {
	z := c.notSyncUpload.Add(int64(d))
	if z >= SyncThreshold && c.syncingUpload.CompareAndSwap(false, true) {
		c.cache.Put(UploadKey, binary.BigEndian.AppendUint64(nil, c.upload.Add(uint64(z))))
		c.notSyncUpload.Add(-z)
		c.syncingUpload.Store(false)
	}
}

func (c *TotalCache) LoadUpload() uint64 { return c.upload.Load() + uint64(c.notSyncUpload.Load()) }

func (c *TotalCache) Close() {
	c.cache.Put(DownloadKey, binary.BigEndian.AppendUint64(nil, c.download.Add(uint64(c.notSyncDownload.Load()))))
	c.cache.Put(UploadKey, binary.BigEndian.AppendUint64(nil, c.upload.Add(uint64(c.notSyncUpload.Load()))))
}
