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
func getRealSizeOf(v interface{}) int {
	b := new(bytes.Buffer)
	if err := gob.NewEncoder(b).Encode(v); err != nil {
		return 0
	}
	return b.Len()
}
