package syncmap

import (
	"fmt"
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestSyncMap(t *testing.T) {
	var syncMap SyncMap[int, int]
	syncMap.Store(1, 1)
	syncMap.Store(2, 2)
	v, _ := syncMap.Load(1)
	assert.Equal(t, v, 1)
	v, _ = syncMap.Load(2)
	assert.Equal(t, v, 2)
}

func TestLoadOrCreate(t *testing.T) {
	var syncMap SyncMap[int, int]
	var wg sync.WaitGroup

	var cache sync.Map

	for j := range 10 {
		key := fmt.Sprintf("case-%d", j)
		t.Run(key, func(t *testing.T) {
			for i := range 10 {
				wg.Go(func() {
					r, _, _ := syncMap.LoadOrCreate(j, func() (int, error) {
						t.Parallel()
						return i, nil
					})
					v, ok := cache.LoadOrStore(key, r)
					if ok {
						assert.Equal(t, v.(int), r)
					}
				})
			}
			wg.Wait()
		})
	}
}
