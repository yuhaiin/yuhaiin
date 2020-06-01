package common

import (
	"testing"
	"time"
)

func TestNewCacheExtend(t *testing.T) {
	x := NewCacheExtend(time.Second * 5)
	x.Add("aa", "aa")
	t.Log(x.Get("aa"))
	t.Log(x.Get("aa"))
	t.Log(x.Get("aa"))
	t.Log(x.Get("aa"))
	time.Sleep(time.Second * 6)
	t.Log(x.Get("aa"))
}
