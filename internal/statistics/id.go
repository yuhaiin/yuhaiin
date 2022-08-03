package statistics

import "sync/atomic"

type IDGenerator struct {
	node atomic.Int64
}

func (i *IDGenerator) Generate() (id int64) {
	return i.node.Add(1)
}
