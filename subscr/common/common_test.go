package common

import "testing"

func TestInt2str(t *testing.T) {
	t.Log(I2string(nil))
	t.Log(I2string("a"))
}
