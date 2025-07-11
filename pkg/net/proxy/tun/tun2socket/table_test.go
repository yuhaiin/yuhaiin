package tun2socket

import (
	"context"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestTable(t *testing.T) {
	t.Run("expire", func(t *testing.T) {
		defaultTableSize = 2
		defaultExpire = time.Second * 2

		table := newTable()
		port := table.portOf(Tuple{SourcePort: uint16(1)})

		time.Sleep(time.Second * 3)

		assert.MustEqual(t, 1, table.v4.set.Len())

		table.v4.set.Range(func(p uint16) bool {
			assert.MustEqual(t, port, p)
			return true
		})

		assert.Equal(t, zeroTuple, table.tupleOf(port, false))
	})

	t.Run("not expire", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		defaultTableSize = 2
		defaultExpire = time.Second * 2

		table := newTable()
		port := table.portOf(Tuple{SourcePort: uint16(1)})

		go func() {
			ticker := time.NewTicker(time.Second * 1)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					table.portOf(Tuple{SourcePort: uint16(1)})
				}
			}
		}()
		time.Sleep(time.Second * 3)

		assert.Equal(t, Tuple{SourcePort: uint16(1)}, table.tupleOf(port, false))
	})
}
