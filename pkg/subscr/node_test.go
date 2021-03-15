package subscr

import (
	"testing"
)

func mapc(a map[string]string) {
	a["a"] = "a"
}

func TestMap(t *testing.T) {
	b := map[string]string{}
	mapc(b)
	t.Log(b["a"])
}
