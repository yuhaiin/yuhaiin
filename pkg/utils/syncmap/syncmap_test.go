package syncmap

import (
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
