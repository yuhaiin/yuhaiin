package assert

import "testing"

func TestEqual(t *testing.T) {
	Equal(t, 2, 1)
	Equal(t, "a", "a")
}
