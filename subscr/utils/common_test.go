package utils

import "testing"

func TestInt2str(t *testing.T) {
	t.Log(I2String(nil))
	t.Log(I2String("a"))
}
