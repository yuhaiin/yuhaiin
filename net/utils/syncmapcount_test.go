package utils

import "testing"

func TestMap_Length(t *testing.T) {
	x := new(Map)
	t.Log(x.Length())
	x.Store("a", "")
	x.Store("a", "")
	x.Store("a", "")
	x.Store("a", "")
	x.Store("b", "")
	t.Log(x.Length())
	x.Delete("a")
	t.Log(x.Length())
	x.Store("aa", "a")
	x.Store("aa", "a")
	x.Store("aa", "a")
	x.Store("aa", "a")
	x.Store("bb", "b")
	t.Log(x.Length())
}
