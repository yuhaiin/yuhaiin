package app

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/internal/config"
)

func TestShunt(t *testing.T) {
	x, err := NewShunt(&config.Config{})
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(x.Get("sp0.baidu.com"))
	t.Log(x.Get("www.baidu.com"))
	t.Log(x.Get("www.google.com"))
}
