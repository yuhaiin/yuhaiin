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

	for j := range 10 {
		t.Run(fmt.Sprintf("case-%d", j), func(t *testing.T) {
			for i := range 10 {
				wg.Add(1)
				go func() {
					defer wg.Done()

					_, _, _ = syncMap.LoadOrCreate(j, func() (int, error) {
						t.Parallel()
						return i, nil
					})

				}()
			}

			wg.Wait()
		})
	}
}
