package pebble

import "testing"

func TestClearWithWALDisabled(t *testing.T) {
	cache, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()

	if err := cache.Put([]byte("key"), []byte("value")); err != nil {
		t.Fatal(err)
	}
	if err := cache.Clear(); err != nil {
		t.Fatalf("Clear failed with WAL disabled: %v", err)
	}
	value, err := cache.Get([]byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	if value != nil {
		t.Fatalf("Clear left value behind: %q", value)
	}
}
