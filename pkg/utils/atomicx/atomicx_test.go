package atomicx

import "testing"

func TestAtomicx(t *testing.T) {
	z := NewValue(1)
	t.Log(z.Load())
	z.Store(2)
	t.Log(z.Load())
}
