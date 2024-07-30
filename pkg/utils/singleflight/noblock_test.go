package singleflight

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestNoBlock(t *testing.T) {
	var g GroupNoblock[int, int]

	c := atomic.Uint32{}
	do := func() {
		g.DoBackground(1,
			func(i int) {
				c.Add(1)
			},
			func() (int, bool) {
				time.Sleep(time.Second)
				t.Log("real do")
				return 1, true
			})
	}

	for range 1000 {
		go do()
	}

	do()

	time.Sleep(time.Second * 2)

	assert.MustEqual(t, c.Load(), uint32(1001))
}
