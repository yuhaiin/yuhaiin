package statistics

import (
	"context"
	"encoding/binary"
	"io"
	"iter"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	"google.golang.org/protobuf/proto"
)

type InfoCache interface {
	Load(id uint64) (*statistic.Connection, bool)
	Store(id uint64, info *statistic.Connection)
	Delete(id uint64)
	io.Closer
}

var _ InfoCache = (*store)(nil)

type store struct {
	ctx   context.Context
	cache cache.Cache

	cancel    context.CancelFunc
	deleteIds deleteIds
	memcache  syncmap.SyncMap[uint64, *statistic.Connection]

	deleteIdsMu sync.Mutex
	closed      atomic.Bool
}

func newInfoStore(cache cache.Cache) *store {
	ctx, cancel := context.WithCancel(context.TODO())
	c := &store{
		cache:     cache,
		ctx:       ctx,
		cancel:    cancel,
		deleteIds: make(map[uint64]struct{}),
	}

	go func() {
		ticker := time.NewTicker(time.Minute * 2)
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

func (c *store) Load(id uint64) (*statistic.Connection, bool) {
	if c.closed.Load() {
		return nil, false
	}

	cc, ok := c.memcache.Load(id)
	if ok {
		return cc, true
	}

	data, err := c.cache.Get(binary.BigEndian.AppendUint64(nil, id))
	if err != nil {
		log.Warn("get info failed", "id", id, "err", err)
		return nil, false
	}

	info := &statistic.Connection{}
	if err := proto.Unmarshal(data, info); err != nil {
		log.Warn("unmarshal info failed", "id", id, "err", err)
		return nil, false
	}

	return info, true
}

func (c *store) Store(id uint64, info *statistic.Connection) {
	if c.closed.Load() {
		return
	}

	c.memcache.Store(id, info)
}

func (c *store) Flush() {
	if c.closed.Load() {
		return
	}

	err := c.cache.Batch(func(txn cache.Batch) error {
		for id := range c.memcache.Range {
			info, ok := c.memcache.LoadAndDelete(id)
			if !ok {
				continue
			}

			data, err := proto.Marshal(info)
			if err != nil {
				log.Warn("marshal info failed", "id", id, "err", err)
				continue
			}

			if err := txn.Put(binary.BigEndian.AppendUint64(nil, id), data); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		log.Warn("put info failed", "err", err)
	}

	c.deleteIdsMu.Lock()
	deleteIds := c.deleteIds
	c.deleteIds = make(map[uint64]struct{})
	c.deleteIdsMu.Unlock()

	if len(deleteIds) > 0 {
		c.cache.Batch(func(txn cache.Batch) error {
			for v := range deleteIds {
				if err := txn.Delete(binary.BigEndian.AppendUint64(nil, v)); err != nil {
					return err
				}
			}

			return nil
		})
	}
}

func (c *store) Delete(id uint64) {
	if c.closed.Load() {
		return
	}

	c.deleteIdsMu.Lock()
	c.deleteIds[id] = struct{}{}
	c.deleteIdsMu.Unlock()

	c.memcache.Delete(id)
}

func (c *store) Close() error {
	c.cancel()
	c.closed.Store(true)
	return nil
}

type deleteIds map[uint64]struct{}

func (c deleteIds) Range() iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		for id := range c {
			if !yield(binary.BigEndian.AppendUint64(nil, id)) {
				break
			}
		}
	}
}

type diskStore struct {
	cache cache.Cache
}

func newDiskInfoStore(cache cache.Cache) *diskStore {
	return &diskStore{
		cache: cache,
	}
}

func (d *diskStore) Load(id uint64) (*statistic.Connection, bool) {
	data, err := d.cache.Get(binary.BigEndian.AppendUint64(nil, id))
	if err != nil {
		log.Warn("get info failed", "id", id, "err", err)
		return nil, false
	}

	info := &statistic.Connection{}
	if err := proto.Unmarshal(data, info); err != nil {
		log.Warn("unmarshal info failed", "id", id, "err", err)
		return nil, false
	}

	return info, true
}

func (d *diskStore) Store(id uint64, info *statistic.Connection) {
	data, err := proto.Marshal(info)
	if err != nil {
		log.Warn("marshal info failed", "id", id, "err", err)
		return
	}

	err = d.cache.Put(binary.BigEndian.AppendUint64(nil, id), data)
	if err != nil {
		log.Warn("put info failed", "err", err)
	}
}

func (d *diskStore) Delete(id uint64) {
	err := d.cache.Delete(binary.BigEndian.AppendUint64(nil, id))
	if err != nil {
		log.Warn("delete info failed", "err", err)
	}
}

func (d *diskStore) Close() error {
	return nil
}
