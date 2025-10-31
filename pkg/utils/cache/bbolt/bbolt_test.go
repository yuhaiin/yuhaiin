package bbolt

import (
	"os"
	"path/filepath"
	"testing"

	"iter"

	"go.etcd.io/bbolt"
)

// setupTestDB creates a temporary bbolt database for testing.
func setupTestDB(tb testing.TB) (*bbolt.DB, func()) {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "test.db")
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		tb.Fatalf("failed to open bbolt db: %v", err)
	}
	return db, func() {
		_ = db.Close()
		_ = os.RemoveAll(path)
	}
}

func TestCacheOperations(t *testing.T) {
	t.Run("TestNewCache", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		cache := NewCache(db, "test_bucket")
		if cache == nil {
			t.Fatal("NewCache returned nil")
		}
		if cache.db != db {
			t.Errorf("NewCache did not set the correct database")
		}
		if len(cache.bucketName) != 1 || string(cache.bucketName[0]) != "test_bucket" {
			t.Errorf("NewCache did not set the correct bucket name, got: %v", cache.bucketName)
		}

		// Test with multiple bucket names
		cacheMulti := NewCache(db, "parent_bucket", "child_bucket")
		if cacheMulti == nil {
			t.Fatal("NewCache with multiple buckets returned nil")
		}
		if len(cacheMulti.bucketName) != 2 || string(cacheMulti.bucketName[0]) != "parent_bucket" || string(cacheMulti.bucketName[1]) != "child_bucket" {
			t.Errorf("NewCache with multiple buckets did not set the correct bucket names, got: %v", cacheMulti.bucketName)
		}
	})

	t.Run("TestCachePutGet", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		cache := NewCache(db, "test_bucket")

		key := []byte("test_key")
		value := []byte("test_value")

		// Test Put
		var err error
		err = cache.Put(func() iter.Seq2[[]byte, []byte] {
			return func(yield func([]byte, []byte) bool) {
				yield(key, value)
			}
		}())
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		// Test Get
		var retrievedValue []byte
		retrievedValue, err = cache.Get(key)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if string(retrievedValue) != string(value) {
			t.Errorf("Get returned wrong value, got %s, want %s", retrievedValue, value)
		}

		// Test Get for non-existent key
		nonExistentKey := []byte("non_existent_key")
		retrievedValue, err = cache.Get(nonExistentKey)
		if err != nil {
			t.Fatalf("Get for non-existent key failed: %v", err)
		}
		if retrievedValue != nil {
			t.Errorf("Get for non-existent key returned non-nil value: %s", retrievedValue)
		}
	})

	t.Run("TestCacheDelete", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		cache := NewCache(db, "test_bucket")

		key := []byte("test_key_to_delete")
		value := []byte("test_value")

		var err error
		err = cache.Put(func() iter.Seq2[[]byte, []byte] {
			return func(yield func([]byte, []byte) bool) {
				yield(key, value)
			}
		}())
		if err != nil {
			t.Fatalf("Put failed: %v", err)
		}

		// Verify it exists
		var retrievedValue []byte
		retrievedValue, err = cache.Get(key)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if retrievedValue == nil {
			t.Fatal("Key not found before deletion")
		}

		// Test Delete
		err = cache.Delete(key)
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		// Verify it's deleted
		retrievedValue, err = cache.Get(key)
		if err != nil {
			t.Fatalf("Get after delete failed: %v", err)
		}
		if retrievedValue != nil {
			t.Errorf("Key found after deletion: %s", retrievedValue)
		}
	})

	t.Run("TestCacheRange", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		cache := NewCache(db, "test_bucket")

		data := map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		}

		var err error
		for k, v := range data {
			err = cache.Put(func() iter.Seq2[[]byte, []byte] {
				return func(yield func([]byte, []byte) bool) {
					yield([]byte(k), []byte(v))
				}
			}())
			if err != nil {
				t.Fatalf("Put failed for %s: %v", k, err)
			}
		}

		foundCount := 0
		err = cache.Range(func(k, v []byte) bool {
			expectedValue, ok := data[string(k)]
			if !ok {
				t.Errorf("Range found unexpected key: %s", k)
				return false
			}
			if string(v) != expectedValue {
				t.Errorf("Range found wrong value for key %s, got %s, want %s", k, v, expectedValue)
				return false
			}
			foundCount++
			return true
		})
		if err != nil {
			t.Fatalf("Range failed: %v", err)
		}
		if foundCount != len(data) {
			t.Errorf("Range found %d items, want %d", foundCount, len(data))
		}

		// Test Range with early exit
		foundCount = 0
		err = cache.Range(func(k, v []byte) bool {
			foundCount++
			return false // Exit early
		})
		if err == nil {
			t.Fatal("Range with early exit did not return error")
		}
		if foundCount != 1 {
			t.Errorf("Range with early exit called callback %d times, want 1", foundCount)
		}
	})

	t.Run("TestCacheNewCacheRecursive", func(t *testing.T) {
		db, cleanup := setupTestDB(t)
		defer cleanup()

		rootCache := NewCache(db, "root_bucket")
		if rootCache == nil {
			t.Fatal("rootCache is nil")
		}

		childCache := rootCache.NewCache("child_bucket").(*Cache)
		if childCache == nil {
			t.Fatal("childCache is nil")
		}
		if childCache.db != db {
			t.Errorf("childCache did not inherit the correct database")
		}
		if len(childCache.bucketName) != 2 || string(childCache.bucketName[0]) != "root_bucket" || string(childCache.bucketName[1]) != "child_bucket" {
			t.Errorf("childCache did not set the correct bucket names, got: %v", childCache.bucketName)
		}

		key := []byte("recursive_key")
		value := []byte("recursive_value")

		var err error
		err = childCache.Put(func() iter.Seq2[[]byte, []byte] {
			return func(yield func([]byte, []byte) bool) {
				yield(key, value)
			}
		}())
		if err != nil {
			t.Fatalf("Put to childCache failed: %v", err)
		}

		var retrievedValue []byte
		retrievedValue, err = childCache.Get(key)
		if err != nil {
			t.Fatalf("Get from childCache failed: %v", err)
		}
		if string(retrievedValue) != string(value) {
			t.Errorf("Get from childCache returned wrong value, got %s, want %s", retrievedValue, value)
		}

		// Ensure rootCache doesn't see the key
		var rootRetrievedValue []byte
		rootRetrievedValue, err = rootCache.Get(key)
		if err != nil {
			t.Fatalf("Get from rootCache failed: %v", err)
		}
		if rootRetrievedValue != nil {
			t.Errorf("rootCache unexpectedly found key: %s", rootRetrievedValue)
		}
	})
}

func BenchmarkCacheOperations(b *testing.B) {
	b.Run("BenchmarkCachePut", func(b *testing.B) {
		db, cleanup := setupTestDB(b)
		defer cleanup()

		cache := NewCache(db, "benchmark_bucket")
		key := []byte("benchmark_key")
		value := []byte("benchmark_value")

		b.ResetTimer()
		for b.Loop() {
			err := cache.Put(func() iter.Seq2[[]byte, []byte] {
				return func(yield func([]byte, []byte) bool) {
					yield(key, value)
				}
			}())
			if err != nil {
				b.Fatalf("Put failed: %v", err)
			}
		}
	})

	b.Run("BenchmarkCacheGet", func(b *testing.B) {
		db, cleanup := setupTestDB(b)
		defer cleanup()

		cache := NewCache(db, "benchmark_bucket")
		key := []byte("benchmark_key")
		value := []byte("benchmark_value")

		var err error
		err = cache.Put(func() iter.Seq2[[]byte, []byte] {
			return func(yield func([]byte, []byte) bool) {
				yield(key, value)
			}
		}())
		if err != nil {
			b.Fatalf("Put failed: %v", err)
		}

		b.ResetTimer()
		for b.Loop() {
			_, err = cache.Get(key)
			if err != nil {
				b.Fatalf("Get failed: %v", err)
			}
		}
	})
}
