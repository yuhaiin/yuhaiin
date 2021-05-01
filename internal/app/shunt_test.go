package app

import (
	"testing"
)

func TestShunt(t *testing.T) {
	x, err := NewShunt("/tmp/yuhaiin_my.conf", nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(x.Get("sp0.baidu.com"))
	t.Log(x.Get("www.baidu.com"))
	t.Log(x.Get("www.google.com"))
}
