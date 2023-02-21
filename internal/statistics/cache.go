package statistics

import (
	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
)

var (
	DownloadKey = []byte{'D', 'O', 'W', 'N', 'L', 'O', 'A', 'D'}
	UploadKey   = []byte{'U', 'P', 'L', 'O', 'A', 'D'}

	SyncThreshold     int64 = 1024 * 1024 * 50 // bytes
	SyncThresholdTime       = time.Minute * 10
)

type Cache struct {
	download atomic.Uint64
	upload   atomic.Uint64

	notSyncDownload atomic.Int64
	notSyncUpload   atomic.Int64

	lastSyncDownloadTime atomic.Pointer[time.Time]
	lastSyncUploadTime   atomic.Pointer[time.Time]

	cache *cache.Cache
}

func NewCache(cache *cache.Cache) *Cache {
	c := &Cache{
		cache: cache,
	}

	now := time.Now()
	c.lastSyncDownloadTime.Store(&now)
	c.lastSyncUploadTime.Store(&now)

	if download := cache.Get(DownloadKey); download != nil {
		c.download.Store(binary.BigEndian.Uint64(download))
	}

	if upload := cache.Get(UploadKey); upload != nil {
		c.upload.Store(binary.BigEndian.Uint64(upload))
	}

	return c
}
func (c *Cache) AddDownload(d uint64) {
	c.download.Add(d)

	z := c.notSyncDownload.Add(int64(d))
	now := time.Now()
	if z >= SyncThreshold || now.Sub(*c.lastSyncDownloadTime.Load()) > SyncThresholdTime {
		c.notSyncDownload.Add(-z)

		c.lastSyncDownloadTime.Store(&now)
		c.cache.Put(DownloadKey, binary.BigEndian.AppendUint64(nil, c.download.Load()))
	}
}

func (c *Cache) LoadDownload() uint64 { return c.download.Load() }

func (c *Cache) AddUpload(d uint64) {
	c.upload.Add(d)

	z := c.notSyncUpload.Add(int64(d))
	now := time.Now()
	if z >= SyncThreshold || now.Sub(*c.lastSyncUploadTime.Load()) > SyncThresholdTime {
		c.cache.Put(UploadKey, binary.BigEndian.AppendUint64(nil, c.upload.Load()))
		c.notSyncUpload.Add(-z)
		c.lastSyncUploadTime.Store(&now)
	}
}

func (c *Cache) LoadUpload() uint64 { return c.upload.Load() }

func (c *Cache) Close() {
	c.cache.Put(DownloadKey, binary.BigEndian.AppendUint64(nil, c.download.Load()))
	c.cache.Put(UploadKey, binary.BigEndian.AppendUint64(nil, c.upload.Load()))
}
