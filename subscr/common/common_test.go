package common

import "testing"

func TestInt2str(t *testing.T) {
	t.Log(interface2string(nil))
	t.Log(interface2string("a"))
}
