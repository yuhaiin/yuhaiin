package utils

import (
	"testing"
)

func TestReducedUnit(t *testing.T) {
	s := []string{"a", "b", "z", "c", "d"}
	t.Log(s[:2], s[2:])
	t.Log(ReducedUnit(2065))
	t.Log(ReducedUnit(10240000))
}

func TestM(t *testing.T) {
	z := make([]byte, 10)
	x := z[5:]

	x[0] = 0x01
	x[1] = 0x02
	x[3] = 0x03

	t.Log(z, x)

}
