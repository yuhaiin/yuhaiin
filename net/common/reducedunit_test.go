package common

import "testing"

func TestReducedUnit(t *testing.T) {
	t.Log(ReducedUnit(2065))
	t.Log(ReducedUnit(10240000))
	t.Log(ReducedUnit2(265))
	t.Log(ReducedUnit2(2065))
	t.Log(ReducedUnit2(10240000))
	t.Log(ReducedUnit2(1024000099999))
	t.Log(ReducedUnit2(102400009999999))
	t.Log(ReducedUnit2(102400009999999999))
}

func BenchmarkReducedUnit(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		ReducedUnit2(102400009999999999)
	}
}
