package device

import (
	"bytes"
	"sync"
	"testing"
)

func TestMultiQueueReadSlab(t *testing.T) {
	payloads := [][]byte{[]byte("queue zero"), []byte("queue one")}
	d := &multiQueueTUN{offset: tunVnetHdrLen}
	for _, payload := range payloads {
		d.devices = append(d.devices, NewDevice(&slabTestDevice{payloads: [][]byte{payload}}, d.offset, 1500, true))
	}
	var workers sync.WaitGroup
	for queue, payload := range payloads {
		workers.Go(func() {
			bufs := [][]byte{make([]byte, 1500+d.offset)}
			sizes := make([]int, 1)
			for range 10 {
				n, err := d.ReadQueue(queue, bufs, sizes)
				if err != nil || n != 1 || !bytes.Equal(bufs[0][d.offset:d.offset+sizes[0]], payload) {
					t.Errorf("queue %d: ReadQueue() = %d, %v, sizes=%v", queue, n, err, sizes)
					return
				}
			}
		})
	}
	workers.Wait()
	for _, queue := range []int{-1, len(d.devices)} {
		if _, err := d.ReadQueue(queue, nil, nil); err == nil {
			t.Errorf("queue %d: expected invalid index error", queue)
		}
	}
}
