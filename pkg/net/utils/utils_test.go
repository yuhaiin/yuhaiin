package utils

import (
	"testing"
)

func TestReducedUnit(t *testing.T) {
	s := []string{"a", "b", "z", "c", "d"}
	t.Log(s[:2], s[2:])
	t.Log(ReducedUnit(2065))
	t.Log(ReducedUnit(10240000))
	t.Log(ReducedUnitToString(265))
	t.Log(ReducedUnitToString(2065))
	t.Log(ReducedUnitToString(10240000))
	t.Log(ReducedUnitToString(1024000099999))
	t.Log(ReducedUnitToString(102400009999999))
	t.Log(ReducedUnitToString(102400009999999999))
}

func BenchmarkReducedUnit(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		ReducedUnitToString(102400009999999999)
	}
}

func TestM(t *testing.T) {
	z := make([]byte, 10)
	x := z[5:]

	x[0] = 0x01
	x[1] = 0x02
	x[3] = 0x03

	t.Log(z, x)

}
