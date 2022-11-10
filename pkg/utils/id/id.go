package id

import "sync/atomic"

type IDGenerator struct {
	node atomic.Uint64
}

func (i *IDGenerator) Generate() (id uint64) {
	return i.node.Add(1)
}
