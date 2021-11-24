package app

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/internal/config"
)

func TestShunt(t *testing.T) {
	x, err := NewShunt(&config.Config{}, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(x.Get("sp0.baidu.com"))
	t.Log(x.Get("www.baidu.com"))
	t.Log(x.Get("www.google.com"))
}

func TestMode(t *testing.T) {
	v := (interface{})(nil)

	v, ok := v.(MODE)
	if !ok {
		t.Log("!OK", v)
	} else {
		t.Log("OK", v)
	}
}
