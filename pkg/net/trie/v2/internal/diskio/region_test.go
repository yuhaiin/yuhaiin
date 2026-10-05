package diskio

import (
	"bytes"
	"io"
	"os"
	"testing"
)

func TestRegionBoundsAndFallback(t *testing.T) {
	path := t.TempDir() + "/segment"
	if err := os.WriteFile(path, []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, fallback := range []bool{false, true} {
		var region *Region
		var err error
		if fallback {
			var f *os.File
			f, err = os.Open(path)
			region = &Region{file: f, Size: 10}
		} else {
			region, err = OpenRegion(path)
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range []struct {
			offset, size uint64
			valid        bool
		}{
			{2, 3, true}, {10, 0, true}, {10, 1, false}, {11, 0, false}, {1, ^uint64(0), false}, {^uint64(0), 1, false},
		} {
			data, ok := region.BytesAt(item.offset, item.size)
			if ok != item.valid {
				t.Fatalf("BytesAt(%d,%d) valid=%v", item.offset, item.size, ok)
			}
			reader, readable := region.Reader(item.offset, item.size)
			if readable != item.valid {
				t.Fatalf("Reader valid=%v", readable)
			}
			if readable {
				read, err := io.ReadAll(reader)
				if err != nil || !bytes.Equal(read, data) {
					t.Fatalf("Reader=%q, %v", read, err)
				}
			}
			view, mapped := region.MappedBytes(item.offset, item.size)
			if mapped && (fallback || !bytes.Equal(view, data)) {
				t.Fatalf("MappedBytes=%q", view)
			}
			if item.valid && !bytes.Equal(data, []byte("0123456789")[item.offset:item.offset+item.size]) {
				t.Fatalf("BytesAt = %q", data)
			}
		}
		if err := region.Close(); err != nil {
			t.Fatal(err)
		}
		if err := region.Close(); err != nil {
			t.Fatal(err)
		}
		if _, ok := region.BytesAt(0, 1); ok {
			t.Fatal("read after Close succeeded")
		}
	}
}
