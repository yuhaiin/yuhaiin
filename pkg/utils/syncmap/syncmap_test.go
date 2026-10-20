package syncmap

import (
	"fmt"
	"sync"
	"sync/atomic"
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
	for j := range 10 {
		key := fmt.Sprintf("case-%d", j)
		t.Run(key, func(t *testing.T) {
			var wg sync.WaitGroup
			var creators atomic.Int32
			start := make(chan struct{})
			results := make(chan int, 10)
			for i := range 10 {
				wg.Go(func() {
					<-start
					r, _, err := syncMap.LoadOrCreate(j, func() (int, error) {
						creators.Add(1)
						return i, nil
					})
					if err != nil {
						t.Errorf("LoadOrCreate: %v", err)
					}
					results <- r
				})
			}
			close(start)
			wg.Wait()
			close(results)

			var first int
			gotFirst := false
			for result := range results {
				if !gotFirst {
					first, gotFirst = result, true
					continue
				}
				assert.Equal(t, result, first)
			}
			if !gotFirst {
				t.Fatal("no LoadOrCreate result")
			}
			if got := creators.Load(); got != 1 {
				t.Fatalf("creator called %d times, want 1", got)
			}
		})
	}
}
