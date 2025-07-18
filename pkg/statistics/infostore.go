package statistics

import (
	"context"
	"encoding/binary"
	"io"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

type InfoCache interface {
	Load(id uint64) (*statistic.Connection, bool)
	Store(id uint64, info *statistic.Connection)
	Delete(id uint64)
	io.Closer
}

var _ InfoCache = (*infoStore)(nil)

type infoStore struct {
	ctx      context.Context
	cancel   context.CancelFunc
	memcache syncmap.SyncMap[uint64, *statistic.Connection]
	closed   atomic.Bool
	cache    cache.Cache
}

func newInfoStore(cache cache.Cache) *infoStore {
	ctx, cancel := context.WithCancel(context.TODO())
	c := &infoStore{
		cache:  cache,
		ctx:    ctx,
		cancel: cancel,
	}

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.Flush()
			}
		}
	}()

	return c
}

func (c *infoStore) Load(id uint64) (*statistic.Connection, bool) {
	if c.closed.Load() {
		return nil, false
	}

	cc, ok := c.memcache.Load(id)
	if ok {
		return cc, true
	}

	data, err := c.cache.Get(binary.BigEndian.AppendUint64([]byte{}, id))
	if err != nil {
		log.Warn("get info failed", "id", id, "err", err)
		return nil, false
	}
	var info statistic.Connection
	if err := proto.Unmarshal(data, &info); err != nil {
		log.Warn("unmarshal info failed", "id", id, "err", err)
		return nil, false
	}

	return &info, true
}

func (c *infoStore) Store(id uint64, info *statistic.Connection) {
	if c.closed.Load() {
		return
	}

	c.memcache.Store(id, info)
}

func (c *infoStore) Flush() {
	if c.closed.Load() {
		return
	}

	deleteIds := make([][]byte, 0)
	err := c.cache.Put(func(yield func([]byte, []byte) bool) {
		for id := range c.memcache.Range {
			info, ok := c.memcache.LoadAndDelete(id)
			if !ok {
				continue
			}

			key := binary.BigEndian.AppendUint64([]byte{}, id)

			if info == nil {
				deleteIds = append(deleteIds, key)
				continue
			}

			data, err := proto.Marshal(info)
			if err != nil {
				log.Warn("marshal info failed", "id", id, "err", err)
				continue
			}

			if !yield(key, data) {
				break
			}
		}
	})
	if err != nil {
		log.Warn("put info failed", "err", err)
	}

	if len(deleteIds) > 0 {
		c.cache.Delete(deleteIds...)
	}
}

func (c *infoStore) Delete(id uint64) {
	if c.closed.Load() {
		return
	}

	_, ok := c.memcache.LoadAndDelete(id)
	if ok {
		return
	}

	c.memcache.Store(id, nil)
}

func (c *infoStore) Close() error {
	c.cancel()
	c.closed.Store(true)
	return c.cache.Close()
}

var _ InfoCache = (*infoMemStore)(nil)

type infoMemStore struct {
	syncmap.SyncMap[uint64, *statistic.Connection]
}

func newInfoMemStore() *infoMemStore { return &infoMemStore{} }

func (c *infoMemStore) Close() error { return nil }
