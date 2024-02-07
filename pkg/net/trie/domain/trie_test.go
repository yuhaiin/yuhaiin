package domain

import (
	"bytes"
	"encoding/gob"
	"testing"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
)

func TestAl(t *testing.T) {
	z := trie[bypass.Mode]{
		Child: map[string]*trie[bypass.Mode]{
			"a": {},
		},
	}
	t.Log(unsafe.Alignof(z), unsafe.Sizeof(z.Child), unsafe.Sizeof(z.Value), unsafe.Sizeof(z))
	zstr := "telegram"
	zmap := map[string]string{
		"tag": "telegram",
	}

	t.Log(unsafe.Sizeof(zstr), unsafe.Sizeof(zmap), len(zmap), getRealSizeOf(zstr), getRealSizeOf(zmap))
}

func getRealSizeOf(v any) int {
	b := new(bytes.Buffer)
	if err := gob.NewEncoder(b).Encode(v); err != nil {
		return 0
	}
	return b.Len()
}

func TestDelete(t *testing.T) {
	x := &trie[string]{Child: map[string]*trie[string]{}}
	insert(x, newReader("www.baidu.com"), "baidu")
	insert(x, newReader("www.google.com"), "google")
	insert(x, newReader("www.twitter.com"), "twitter")
	insert(x, newReader("www.x.twitter.com"), "twitter.x")
	insert(x, newReader("*.x.com"), "*.x")
	insert(x, newReader("www.xvv.*"), "xvv.*")

	remove(x, newReader("www.baidu.com"))

	t.Log(search(x, newReader("www.baidu.com")))

	remove(x, newReader("www.twitter.com"))
	remove(x, newReader("www.vv.x.com"))

	t.Log(search(x, newReader("www.twitter.com")))
	t.Log(search(x, newReader("www.x.twitter.com")))
	t.Log(search(x, newReader("www.vv.x.com")))

	remove(x, newReader("*.x.com"))
	t.Log(search(x, newReader("www.vv.x.com")))
	t.Log(search(x, newReader("www.xvv.com.cn")))

	remove(x, newReader("www.xvv.*"))
	t.Log(search(x, newReader("www.xvv.com.cn")))
}
