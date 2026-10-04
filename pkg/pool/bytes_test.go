package pool

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func BenchmarkBytes(b *testing.B) {
	for _, size := range []int{64, 1500, DefaultSize, 65535} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				p := GetBytes(size)
				p[0] = 1
				PutBytes(p)
			}
		})
	}
}

func TestBytesPoolSizesAndOwnership(t *testing.T) {
	PutBytes(nil)
	if GetBytes(0) != nil {
		t.Fatal("zero size must return nil")
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for _, size := range []int{1, 3, 64, 1500, DefaultSize, 65535, 1 << 20, (1 << 20) + 1} {
				for range 10 {
					p := GetBytes(size)
					if len(p) != size || cap(p) < size {
						t.Errorf("invalid length/capacity for %d", size)
						return
					}
					value := byte(worker + 1)
					for i := range p {
						p[i] = value
					}
					if !bytes.Equal(p, bytes.Repeat([]byte{value}, size)) {
						t.Error("pool returned a buffer concurrently owned by another caller")
					}
					PutBytes(p[:0])
				}
			}
		})
	}
	wg.Wait()
	// Returning a caller-allocated, non-power-of-two slice remains supported.
	PutBytes(make([]byte, 37, 1500))
	p := GetBytes(1024)
	if cap(p) != 1024 {
		t.Fatalf("capacity = %d, want bucket capacity 1024", cap(p))
	}
	PutBytes(p)
}
