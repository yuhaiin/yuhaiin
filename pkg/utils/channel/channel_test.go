package channel

import (
	"sync"
	"testing"
)

func TestChannel(t *testing.T) {
	c := NewChannel[string](100)

	go func() {
		for range 500 {
			c.Push("a")
		}

		c.Close()
	}()

	go func() {
		for range 500 {
			c.Push("b")
		}

		c.Close()
	}()

	for c.Pop(12, func(s []string) {
		t.Log(len(s))
	}) {
	}
}

// BenchmarkChannel
// BenchmarkChannel-12    	56181505	        22.08 ns/op	      15 B/op	       0 allocs/op
// BenchmarkChannel
// BenchmarkMyChannel-12    	14072252	        93.82 ns/op	      45 B/op	       0 allocs/op
func BenchmarkMyChannel(b *testing.B) {
	wwg := sync.WaitGroup{}

	c := NewChannel[string](100)

	for range 500 {
		wwg.Add(1)
		go func() {
			defer wwg.Done()
			for range b.N / 100 {
				c.Push("a")
			}
		}()
	}

	go func() {
		wwg.Wait()
		c.Close()
	}()

	wg := sync.WaitGroup{}

	buf := make([]string, 0, 12)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			buf = buf[:0]
			if !c.Pop(12, func(s []string) {
				buf = append(buf, s...)
			}) {
				break
			}
		}
	}()

	wg.Wait()
}

func bumpChannel[T any](bc chan T, max int, f func(T)) bool {
	pkt, ok := <-bc
	if !ok {
		return false
	}

	size := min(len(bc), max-1) + 1

	f(pkt)

	for range size - 1 {
		f(<-bc)
	}

	return true
}

// BenchmarkGoChannel
// BenchmarkGoChannel-12    	52131781	        22.07 ns/op	       0 B/op	       0 allocs/op
// BenchmarkGoChannel
// BenchmarkGoChannel-12    	12657698	       100.4 ns/op	      24 B/op	       0 allocs/op
func BenchmarkGoChannel(b *testing.B) {

	wwg := sync.WaitGroup{}

	c := make(chan string, 100)

	for range 500 {
		wwg.Add(1)
		go func() {
			defer wwg.Done()
			for range b.N / 100 {
				c <- "a"
			}
		}()
	}

	go func() {
		wwg.Wait()
		close(c)
	}()

	wg := sync.WaitGroup{}

	bufs := make([]string, 0, 12)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			x := bumpChannel(c, 12, func(s string) {
				bufs = append(bufs, s)
			})
			bufs = bufs[:0]
			if !x {
				break
			}
		}
	}()

	wg.Wait()
}
