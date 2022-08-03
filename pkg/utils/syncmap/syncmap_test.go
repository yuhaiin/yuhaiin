package syncmap

import "testing"

func TestSyncmap(t *testing.T) {
	var syncMap SyncMap[int, int]
	syncMap.Store(1, 1)
	syncMap.Store(2, 2)
	t.Log(syncMap.Load(1))
	t.Log(syncMap.Load(2))
}
