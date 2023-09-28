package domain

import (
	"bytes"
	"encoding/gob"
	"testing"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
)

func TestAl(t *testing.T) {
	z := domainNode[bypass.Mode]{
		Child: map[string]*domainNode[bypass.Mode]{
			"a": {},
		},
	}
	t.Log(unsafe.Alignof(z), unsafe.Sizeof(z.Child), unsafe.Sizeof(z.Mark), unsafe.Sizeof(z))
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
	x := &domainNode[string]{Child: map[string]*domainNode[string]{}}
	insert(x, newDomainReader("www.baidu.com"), "baidu")
	insert(x, newDomainReader("www.google.com"), "google")
	insert(x, newDomainReader("www.twitter.com"), "twitter")
	insert(x, newDomainReader("www.x.twitter.com"), "twitter.x")
	insert(x, newDomainReader("*.x.com"), "*.x")
	insert(x, newDomainReader("www.xvv.*"), "xvv.*")

	remove(x, newDomainReader("www.baidu.com"))

	t.Log(search(x, newDomainReader("www.baidu.com")))

	remove(x, newDomainReader("www.twitter.com"))
	remove(x, newDomainReader("www.vv.x.com"))

	t.Log(search(x, newDomainReader("www.twitter.com")))
	t.Log(search(x, newDomainReader("www.x.twitter.com")))
	t.Log(search(x, newDomainReader("www.vv.x.com")))

	remove(x, newDomainReader("*.x.com"))
	t.Log(search(x, newDomainReader("www.vv.x.com")))
	t.Log(search(x, newDomainReader("www.xvv.com.cn")))

	remove(x, newDomainReader("www.xvv.*"))
	t.Log(search(x, newDomainReader("www.xvv.com.cn")))
}
