package match

import "testing"

func TestCache(t *testing.T) {
	mCache.Add("test", "mark")
	t.Log(mCache.Get("test"))
	t.Log(mCache.Get("test2"))
}
