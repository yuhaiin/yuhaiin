package pool

import (
	"fmt"
	"testing"
)

func TestBytes(t *testing.T) {
	b := GetBytes(1111)
	t.Log(len(b), cap(b), fmt.Sprintf("%p", b))

	v := nextLogBase2(1111)

	t.Log(v, prevLogBase2(2048))

	PutBytes(b)
	PutBytes(b)
}
