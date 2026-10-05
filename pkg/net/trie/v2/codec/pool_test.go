package codec

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestPooledStringsOwnDataAndDoNotAllocateMarks(t *testing.T) {
	c := UnsafeStringCodec{}
	first, _ := c.Encode([]string{"route-list-a", "route-list-b"})
	second, _ := c.Encode([]string{"route-list-a", ""})
	pool, err := NewPooledStringCodec(bytes.NewReader(append(slices.Clone(first), second...)))
	if err != nil || pool == nil {
		t.Fatalf("pool=%v error=%v", pool, err)
	}
	scratch := make([]string, 0, 2)
	if allocs := testing.AllocsPerRun(100, func() {
		var e error
		scratch, e = pool.AppendDecodeOwned(scratch[:0], first)
		if e != nil {
			t.Fatal(e)
		}
	}); allocs != 0 {
		t.Fatalf("allocs=%g", allocs)
	}
	got, err := pool.Decode(first)
	if err != nil {
		t.Fatal(err)
	}
	clear(first)
	clear(second)
	if !slices.Equal(got, []string{"route-list-a", "route-list-b"}) {
		t.Fatalf("owned values=%q", got)
	}
	unknown, _ := c.Encode([]string{"not-in-dictionary"})
	values, err := pool.AppendDecodeOwned(nil, unknown)
	if err != nil {
		t.Fatal(err)
	}
	clear(unknown)
	if !slices.Equal(values, []string{"not-in-dictionary"}) {
		t.Fatalf("fallback values=%q", values)
	}
}

func TestPooledStringsRespectBounds(t *testing.T) {
	for name, values := range map[string][]string{
		"entry limit": func() []string {
			values := make([]string, stringPoolEntries+1)
			for i := range values {
				values[i] = fmt.Sprintf("mark-%d", i)
			}
			return values
		}(),
		"byte limit": func() []string {
			values := make([]string, 100)
			for i := range values {
				values[i] = fmt.Sprintf("%04d", i) + strings.Repeat("x", 1024)
			}
			return values
		}(),
		"large mark": {strings.Repeat("x", stringPoolBuffer+1)},
	} {
		t.Run(name, func(t *testing.T) {
			data, _ := (UnsafeStringCodec{}).Encode(values)
			pool, err := NewPooledStringCodec(bytes.NewReader(data))
			if pool != nil || err != nil {
				t.Fatalf("pool=%v error=%v", pool, err)
			}
		})
	}
	for _, data := range [][]byte{{1}, {1, 0, 0, 0}, {1, 0, 0, 0, 3, 0, 0, 0, 'a', 'b'}, {0, 0, 0, 0, 1}} {
		if pool, err := NewPooledStringCodec(bytes.NewReader(data)); err == nil {
			t.Fatalf("malformed pool=%v", pool)
		}
	}
}
