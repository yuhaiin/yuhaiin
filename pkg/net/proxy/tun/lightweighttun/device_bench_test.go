package lightweighttun

import "testing"

type batchTestTun struct {
	testTun
	batch int
}

func (d *batchTestTun) BatchSize() int { return d.batch }

// BenchmarkNewPacketIO measures the resident read-buffer cost of a batched,
// non-offload TUN such as macOS utun with experimental batching.
func BenchmarkNewPacketIO(b *testing.B) {
	for _, batch := range []int{1, 64, 128} {
		b.Run(map[int]string{1: "batch1", 64: "batch64", 128: "batch128"}[batch], func(b *testing.B) {
			d := &batchTestTun{testTun: testTun{offset: 4}, batch: batch}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := newPacketIO(d); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
