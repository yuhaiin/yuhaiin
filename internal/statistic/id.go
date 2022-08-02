package statistic

import "sync/atomic"

type idGenerater struct {
	node atomic.Int64
}

func (i *idGenerater) Generate() (id int64) {
	return i.node.Add(1)
}
