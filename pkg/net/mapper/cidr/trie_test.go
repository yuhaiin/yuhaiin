package cidr

import (
	"testing"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
)

func TestAl(t *testing.T) {
	z := Trie[bypass.Mode]{}
	t.Log(unsafe.Alignof(z), unsafe.Sizeof(z.last), unsafe.Sizeof(z.left), unsafe.Sizeof(z))
}
