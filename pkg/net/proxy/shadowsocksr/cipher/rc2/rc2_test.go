package rc2

import "testing"

func TestNew(t *testing.T) {
	t.Log(New([]byte("12345678"), 16))
}
