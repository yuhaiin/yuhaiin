package statistic

import "sync/atomic"

type idGenerater struct {
	node int64
}

func (i *idGenerater) Generate() (id int64) {
	return atomic.AddInt64(&i.node, 1)
}
