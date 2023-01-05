package statistics

import (
	"testing"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

func TestSize(t *testing.T) {
	t.Log(unsafe.Sizeof(statistic.Connection{}))
}
