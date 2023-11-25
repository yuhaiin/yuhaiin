package yuhaiin

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
	"go.etcd.io/bbolt"
)

func InitDB(path string) {
	db, err := app.OpenBboltDB(app.PathGenerator.Cache(path))
	if err != nil {
		log.Error("open bbolt db failed", "err", err)
		panic(err)
	}

	app.App.DB = db
}

type Cache struct {
	cache *cache.Cache
}

func NewCache(name string) *Cache {
	return &Cache{
		cache: cache.NewCache(app.App.DB, fmt.Sprintf("android_%s", name)),
	}
}

func (c *Cache) Put(k, v string)     { c.cache.Put([]byte(k), []byte(v)) }
func (c *Cache) Get(k string) string { return string(c.cache.Get([]byte(k))) }
func (c *Cache) Delete(k string)     { c.cache.Delete([]byte(k)) }

func DeleteCache(name string) {
	_ = app.App.DB.Batch(func(tx *bbolt.Tx) error {
		return tx.DeleteBucket([]byte(name))
	})
}
