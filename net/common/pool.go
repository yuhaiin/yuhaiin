package common

import "sync"

var BuffPool = sync.Pool{New: func() interface{} { return make([]byte, 32*0x400) }}
var CloseSigPool = sync.Pool{New: func() interface{} { return make(chan error, 1) }}