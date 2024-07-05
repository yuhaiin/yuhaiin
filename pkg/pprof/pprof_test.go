package pprof

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

func TestPprof(t *testing.T) {
	ps, err := Merge([]string{"pgo.pprof", "pgo2.pprof"})
	assert.NoError(t, err)

	buf2 := pool.NewBuffer(nil)
	err = ps.Write(buf2)
	assert.NoError(t, err)

	t.Log(buf2.Len())

}
