package utils

import (
	"testing"
)

func TestReducedUnit(t *testing.T) {
	t.Log(ReducedUnit(2065))
	t.Log(ReducedUnit(10240000))
	t.Log(ReducedUnitStr(265))
	t.Log(ReducedUnitStr(2065))
	t.Log(ReducedUnitStr(10240000))
	t.Log(ReducedUnitStr(1024000099999))
	t.Log(ReducedUnitStr(102400009999999))
	t.Log(ReducedUnitStr(102400009999999999))
}

func BenchmarkReducedUnit(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		ReducedUnitStr(102400009999999999)
	}
}
