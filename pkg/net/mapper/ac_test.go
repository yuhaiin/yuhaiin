package mapper

import "testing"

func TestAC(t *testing.T) {
	a := NewAC()

	a.Insert(".baidu.")
	a.Insert(".google.")
	a.Insert("www.google.com")
	a.Insert("music.163.com")
	a.Insert("music.163")
	a.Insert("163.com")
	a.Insert("a")
	a.Insert("aa")
	a.Insert("aaa")
	a.Insert("aaaa")
	a.Insert("aaaaa")
	a.BuildFail()

	t.Log(a.searchLongest("www.baidu.aaaaa.com"))
	t.Log(a.searchLongest("www.google.baidu.com"))
	t.Log(a.searchLongest("www.goaoaga.com"))
	t.Log(a.searchLongest("a.www.google.com"))
	t.Log(a.searchLongest("music.163.com"))
	t.Log(a.searchLongest("s.163.com"))
	t.Log(a.searchLongest("music.163.net"))
}

func TestAC2(t *testing.T) {
	a := NewAC()
	a.Insert("she")
	a.Insert("he")
	a.Insert("hers")
	a.Insert("his")
	a.BuildFail()

	t.Log(a.search("ushers"))
}
