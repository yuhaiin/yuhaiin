package bloom

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"testing"
)

func doubleFNV(b []byte) (uint64, uint64) {
	hx := fnv.New64()
	hx.Write(b)
	x := hx.Sum64()
	hy := fnv.New64a()
	hy.Write(b)
	y := hy.Sum64()
	return x, y
}

func TestClassicFilter_Test(t *testing.T) {
	bf := New(1e6, 1e-4, doubleFNV)
	buf := []byte("testing")
	bf.Add(buf)
	if !bf.Test(buf) {
		t.Fatal("Should exist in filter but got false")
	}
	if bf.Test([]byte("not-exists")) {
		t.Fatal("Should missing in filter but got true")
	}
}

func TestFalsePositive(t *testing.T) {
	const (
		n         = 1e6
		expectFPR = 1e-4
	)
	bf := New(n, expectFPR, doubleFNV)
	samples := make([][]byte, n)
	fp := 0 // false positive count

	for i := 0; i < n; i++ {
		x := []byte(fmt.Sprint(i))
		samples[i] = x
		bf.Add(x)
	}

	for _, x := range samples {
		if !bf.Test(x) {
			fp++
		}
	}
	fpr := float64(fp) / n
	t.Logf("Samples = %d, FP = %d, FPR = %.4f%%", int(n), fp, fpr*100)
}

func BenchmarkAdd(b *testing.B) {
	b.StopTimer()
	b.ReportAllocs()
	bf := New(1e6, 1e-4, doubleFNV)
	buf := make([]byte, 20)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		binary.PutUvarint(buf, uint64(i))
		bf.Add(buf)
	}
}

func BenchmarkTest(b *testing.B) {
	b.StopTimer()
	b.ReportAllocs()
	bf := New(1e6, 1e-4, doubleFNV)
	buf := make([]byte, 20)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		binary.PutUvarint(buf, uint64(i))
		bf.Test(buf)
	}
}
