package common

import "sync"

var (
	BuffPool     = sync.Pool{New: func() interface{} { return make([]byte, 32*0x400) }}
	CloseSigPool = sync.Pool{New: func() interface{} { return make(chan error, 2) }}
	QueuePool    = sync.Pool{New: func() interface{} { return [2]int{} }}
)
