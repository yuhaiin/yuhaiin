package http2

import (
	"container/list"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"golang.org/x/net/http2"
)

// NewRandomWriteScheduler returns a new random write scheduler
//
// for proxy we don't care about the priority, but
// we need care about the fairness among streams
func NewRandomWriteScheduler() http2.WriteScheduler {
	return &randomWriteScheduler{
		zero: list.New(),
		maps: make(map[uint32]*list.List),
	}
}

type randomWriteScheduler struct {
	zero *list.List
	maps map[uint32]*list.List
}

func (ws *randomWriteScheduler) OpenStream(streamID uint32, options http2.OpenStreamOptions) {
	// no-op: idle streams are not tracked
}

func (ws *randomWriteScheduler) CloseStream(streamID uint32) {
	delete(ws.maps, streamID)
}

func (ws *randomWriteScheduler) AdjustStream(streamID uint32, priority http2.PriorityParam) {
	// no-op: priorities are ignored
}

func (ws *randomWriteScheduler) Push(wr http2.FrameWriteRequest) {
	if wr.StreamID() == 0 {
		ws.zero.PushBack(wr)
		return
	}

	queue, ok := ws.maps[wr.StreamID()]
	if !ok {
		queue = list.New()
		ws.maps[wr.StreamID()] = queue
	}

	queue.PushBack(wr)
}

func (ws *randomWriteScheduler) Pop() (http2.FrameWriteRequest, bool) {
	if front := ws.zero.Front(); front != nil {
		v, ok := ws.zero.Remove(front).(http2.FrameWriteRequest)
		if ok {
			return v, true
		}
	}

	for _, v := range ws.maps {
		if v.Len() == 0 {
			continue
		}

		front := v.Front()
		if front == nil {
			continue
		}

		wr, ok := front.Value.(http2.FrameWriteRequest)
		if !ok {
			log.Warn("value is not http2.FrameWriteRequest", "stream", front.Value)
			continue
		}

		consumed, rest, numresult := wr.Consume(int32(pool.DefaultSize))
		switch numresult {
		case 0:
			continue
		case 1:
			v.Remove(front)
		case 2:
			front.Value = rest
		}
		return consumed, true
	}
	return http2.FrameWriteRequest{}, false
}
