package domain

import (
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
}
