package app

import (
	"sync/atomic"
	"testing"
)

// BenchmarkAtomic-4 1000000000 0.0000002ns/op  0B/op  0allocs/op
func BenchmarkAtomic(t *testing.B) {
	var a uint64
	t.ResetTimer()
	t.StopTimer()

	for i := 0; i < t.N; i++ {
		atomic.AddUint64(&a, uint64(i))
	}
}

//BenchmarkChannel-4  16146837  71.30ns/op  0B/op  0allocs/op
func BenchmarkChannel(t *testing.B) {
	var a uint64
	c := make(chan uint64, 100)
	go func() {
		for x := range c {
			atomic.AddUint64(&a, x)
		}
	}()
	for i := 0; i < t.N; i++ {
		c <- uint64(i)
	}
}
