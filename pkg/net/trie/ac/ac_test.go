package ac

import "testing"

func TestAC(t *testing.T) {
	a := NewAC()
	a.Insert("she")
	a.Insert("he")
	a.Insert("hers")
	a.Insert("his")
	a.BuildFail()

	t.Log(a.Search("ushers"))
}
