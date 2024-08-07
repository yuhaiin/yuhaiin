package tun2socket

import (
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestTable(t *testing.T) {
	defaultTableSize = 2
	defaultExpire = time.Second * 2

	table := newTable()
	table.portOf(Tuple{SourcePort: uint16(1)})
	table.portOf(Tuple{SourcePort: uint16(2)})

	time.Sleep(time.Second * 1)
	table.portOf(Tuple{SourcePort: uint16(1)})
	time.Sleep(time.Second * 2)

	assert.MustEqual(t, 1, table.v4.set.Len())

	table.v4.set.Range(func(p uint16) bool {
		assert.MustEqual(t, 10001, p)
		return true
	})
}
