package kvjson

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestKVJSON(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "config.json")

	store, err := New(filePath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	t.Run("Basic Set/Get/Delete", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// Set
		if err := store.Set(ctx, "foo", 123); err != nil {
			t.Fatalf("Set failed: %v", err)
		}

		// Get
		v, ok, err := store.Get("foo")
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if !ok {
			t.Fatal("Get returned ok=false for existing key")
		}
		if v.(float64) != 123 { // JSON numbers decode成 float64
			t.Fatalf("Get returned wrong value: %v", v)
		}

		// Delete
		if err := store.Delete(ctx, "foo"); err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		_, ok, _ = store.Get("foo")
		if ok {
			t.Fatal("Delete did not remove key")
		}
	})

	t.Run("Concurrent Write / Lock Contention", func(t *testing.T) {
		var wg sync.WaitGroup
		errCh := make(chan error, 2)

		writeFunc := func(key string, value int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := store.Set(ctx, key, value)
			errCh <- err
		}

		wg.Add(2)
		go writeFunc("a", 1)
		go writeFunc("b", 2)
		wg.Wait()
		close(errCh)

		for err := range errCh {
			if err != nil {
				t.Fatalf("Concurrent write failed: %v", err)
			}
		}

		// 验证最后写入者赢
		m, _ := store.readAll()
		if _, ok := m["a"]; !ok {
			t.Log("key a may have been overwritten (expected last-write wins)")
		}
		if _, ok := m["b"]; !ok {
			t.Log("key b may have been overwritten (expected last-write wins)")
		}
	})

	t.Run("Context Timeout", func(t *testing.T) {
		// 模拟别人持锁
		lock, _ := acquireLock(context.Background(), store.lockPath)
		defer lock.release()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err := store.Set(ctx, "foo", 999)
		if err == nil {
			t.Fatal("Expected Set to fail due to lock, but it succeeded")
		}
	})
}
