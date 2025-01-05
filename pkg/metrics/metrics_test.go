package metrics

import (
	"math"
	"testing"
)

func TestFloat64(t *testing.T) {
	x := uint64(math.MaxUint64)
	t.Log(float64(x))
}
