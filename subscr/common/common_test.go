package common

import "testing"

func TestInt2str(t *testing.T) {
	t.Log(Interface2string(nil))
	t.Log(Interface2string("a"))
}
