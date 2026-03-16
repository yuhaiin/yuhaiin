package pebble

import (
	"bytes"
	"maps"
	"os"
	"strconv"
	"testing"
)

func setupTestDB(t testing.TB) *Cache {
	t.Helper()
	c, err := New("test.db")
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	t.Cleanup(func() {
		c.Close()
		os.RemoveAll("test.db")
	})
	return c
}

func TestPebble(t *testing.T) {
	t.Run("PutAndGet", func(t *testing.T) {
		c := setupTestDB(t)
		testCases := map[string][]byte{
			"key1": []byte("value1"),
			"key2": []byte("value2"),
			"key3": []byte("value3"),
		}

		for k, v := range testCases {
			err := c.Put([]byte(k), v)
			if err != nil {
				t.Fatalf("Put failed: %v", err)
			}

			got, err := c.Get([]byte(k))
			if err != nil {
				t.Fatalf("Get failed: %v", err)
			}
			if !bytes.Equal(v, got) {
				t.Fatalf("got %s, want %s", got, v)
			}
		}
	})

	t.Run("Range", func(t *testing.T) {
		c := setupTestDB(t)
		testCases := map[string][]byte{
			"key1": []byte("value1"),
			"key2": []byte("value2"),
			"key3": []byte("value3"),
		}
		for k, v := range testCases {
			err := c.Put([]byte(k), v)
			if err != nil {
				t.Fatalf("Put failed: %v", err)
			}
		}

		count := 0
		err := c.Range(func(key []byte, value []byte) bool {
			count++
			if !bytes.Equal(testCases[string(key)], value) {
				t.Errorf("got %s, want %s", value, testCases[string(key)])
			}
			return true
		})
		if err != nil {
			t.Fatalf("Range failed: %v", err)
		}
		if len(testCases) != count {
			t.Fatalf("got %d keys, want %d", count, len(testCases))
		}
	})

	t.Run("Delete", func(t *testing.T) {
		c := setupTestDB(t)
		err := c.Put([]byte("key1"), []byte("value1"))
		if err != nil {
			t.Fatal(err)
		}
		err = c.Delete([]byte("key1"))
		if err != nil {
			t.Fatalf("Delete failed: %v", err)
		}

		v, err := c.Get([]byte("key1"))
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if v != nil {
			t.Fatalf("key1 should be deleted")
		}
	})

	t.Run("Bucket", func(t *testing.T) {
		c := setupTestDB(t)
		bucket1 := c.NewCache("bucket1")

		err := bucket1.Put([]byte("key1"), []byte("value1"))
		if err != nil {
			t.Fatal(err)
		}

		v, err := bucket1.Get([]byte("key1"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal([]byte("value1"), v) {
			t.Fatalf("got %s, want %s", v, []byte("value1"))
		}

		// check that key1 is not in root
		v, err = c.Get([]byte("key1"))
		if err != nil {
			t.Fatal(err)
		}
		if v != nil {
			t.Fatalf("key1 should not be in root")
		}

		// check that key1 is not in bucket2
		bucket2 := c.NewCache("bucket2")
		v, err = bucket2.Get([]byte("key1"))
		if err != nil {
			t.Fatal(err)
		}
		if v != nil {
			t.Fatalf("key1 should not be in bucket2")
		}

		t.Run("DeleteBucket", func(t *testing.T) {
			err = c.DeleteBucket("bucket1")
			if err != nil {
				t.Fatal(err)
			}

			v, err := bucket1.Get([]byte("key1"))
			if err != nil {
				t.Fatal(err)
			}
			if v != nil {
				t.Fatalf("key1 should be deleted from bucket1")
			}
		})
	})

	t.Run("RangeBreak", func(t *testing.T) {
		c := setupTestDB(t)
		expect := map[string]string{}

		for i := range 10 {
			key := "key" + strconv.Itoa(i)
			value := "value" + strconv.Itoa(i)
			expect[key] = value

			err := c.Put([]byte(key), []byte(value))
			if err != nil {
				t.Fatal(err)
			}
		}

		result := map[string]string{}
		err := c.Range(func(key []byte, value []byte) bool {
			result[string(key)] = string(value)
			return len(result) < 5
		})
		if err != nil {
			t.Fatal(err)
		}

		if len(result) != 5 {
			t.Fatal("len of result is not 5")
		}

		for k, v := range result {
			if expect[k] != v {
				t.Fatalf("key %s value not match", k)
			}
		}
	})

	t.Run("NestBucket", func(t *testing.T) {
		c := setupTestDB(t)
		b1 := c.NewCache("b1")
		b2 := b1.NewCache("b2")
		b3 := b2.NewCache("b3")

		err := b3.Put([]byte("key"), []byte("value"))
		if err != nil {
			t.Fatal(err)
		}

		v, err := b3.Get([]byte("key"))
		if err != nil {
			t.Fatal(err)
		}

		if string(v) != "value" {
			t.Fatal("value not match")
		}

		all := map[string]string{}
		err = c.Range(func(key, value []byte) bool {
			all[string(key)] = string(value)
			return true
		})
		if err != nil {
			t.Fatal(err)
		}

		if !maps.Equal(all, map[string]string{"b1/b2/b3/key": "value"}) {
			t.Fatalf("range wrong: %v", all)
		}

		all = map[string]string{}
		err = b1.Range(func(key, value []byte) bool {
			all[string(key)] = string(value)
			return true
		})
		if err != nil {
			t.Fatal(err)
		}

		if !maps.Equal(all, map[string]string{"b2/b3/key": "value"}) {
			t.Fatalf("range wrong: %v", all)
		}

		all = map[string]string{}
		err = b2.Range(func(key, value []byte) bool {
			all[string(key)] = string(value)
			return true
		})
		if err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(all, map[string]string{"b3/key": "value"}) {
			t.Fatalf("range wrong: %v", all)
		}
	})

	t.Run("DeleteBucket", func(t *testing.T) {
		c := setupTestDB(t)
		b1 := c.NewCache("b1")
		b2 := b1.NewCache("b2")
		b3 := b2.NewCache("b3")

		err := b3.Put([]byte("key"), []byte("value"))
		if err != nil {
			t.Fatal(err)
		}

		err = b1.DeleteBucket("b2")
		if err != nil {
			t.Fatal(err)
		}

		v, err := b3.Get([]byte("key"))
		if err != nil {
			t.Fatal(err)
		}

		if v != nil {
			t.Fatal("delete bucket failed")
		}
	})

	t.Run("CacheExists", func(t *testing.T) {
		c := setupTestDB(t)
		b1 := c.NewCache("b1")

		if c.CacheExists("b1") {
			t.Fatal("b1 should not exist yet")
		}

		err := b1.Put([]byte("key"), []byte("value"))
		if err != nil {
			t.Fatal(err)
		}

		if !c.CacheExists("b1") {
			t.Fatal("b1 should exist")
		}

		if c.CacheExists("b2") {
			t.Fatal("b2 should not exist")
		}

		b2 := b1.NewCache("b2")
		if c.CacheExists("b1", "b2") {
			t.Fatal("b1/b2 should not exist yet")
		}

		err = b2.Put([]byte("key"), []byte("value"))
		if err != nil {
			t.Fatal(err)
		}

		if !c.CacheExists("b1", "b2") {
			t.Fatal("b1/b2 should exist")
		}
	})
}

/*
cpu: AMD Ryzen 5 5600G with Radeon Graphics
BenchmarkPebble
BenchmarkPebble/Put
BenchmarkPebble/Put-12         	 1378983	       864.0 ns/op	      19 B/op	       2 allocs/op
BenchmarkPebble/Get
BenchmarkPebble/Get-12         	 9183296	       112.6 ns/op	      31 B/op	       2 allocs/op
BenchmarkPebble/Range
BenchmarkPebble/Range-12       	    1641	    701732 ns/op	  151577 B/op	   10001 allocs/op
BenchmarkPebble/CacheExists
BenchmarkPebble/CacheExists-12 	 2078414	       577.0 ns/op	      40 B/op	       3 allocs/op
*/
func BenchmarkPebble(b *testing.B) {
	b.Run("Put", func(b *testing.B) {
		c := setupTestDB(b)
		b.ResetTimer()
		for i := 0; b.Loop(); i++ {
			key := []byte("key" + strconv.Itoa(i))
			value := []byte("value" + strconv.Itoa(i))
			err := c.Put(key, value)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Get", func(b *testing.B) {
		c := setupTestDB(b)
		for i := range 10000 {
			key := []byte("key" + strconv.Itoa(i))
			value := []byte("value" + strconv.Itoa(i))
			err := c.Put(key, value)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.ResetTimer()

		b.RunParallel(func(pb *testing.PB) {
			for i := 0; pb.Next(); i++ {
				key := []byte("key" + strconv.Itoa(i%10000))
				_, err := c.Get(key)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})

	b.Run("Range", func(b *testing.B) {
		c := setupTestDB(b)
		for i := range 10000 {
			key := []byte("key" + strconv.Itoa(i))
			value := []byte("value" + strconv.Itoa(i))
			err := c.Put(key, value)
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ResetTimer()
		for b.Loop() {
			err := c.Range(func(key []byte, value []byte) bool {
				return true
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("CacheExists", func(b *testing.B) {
		c := setupTestDB(b)
		bucket := c.NewCache("testbucket")
		err := bucket.Put([]byte("key"), []byte("value"))
		if err != nil {
			b.Fatal(err)
		}

		b.ResetTimer()
		for i := 0; b.Loop(); i++ {
			_ = c.CacheExists("testbucket")
		}
	})
}
