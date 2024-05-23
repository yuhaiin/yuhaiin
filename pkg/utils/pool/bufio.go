package pool

import (
	"bufio"
	"io"
	"math/bits"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var bufioReaderPoolMap syncmap.SyncMap[int, *sync.Pool]

func bufioReaderPool(size int) *sync.Pool {
	if v, ok := bufioReaderPoolMap.Load(size); ok {
		return v
	}

	p := &sync.Pool{New: func() any { return bufio.NewReaderSize(nil, size) }}
	poolMap.Store(size, p)
	return p
}

func GetBufioReader(r io.Reader, size int) *bufio.Reader {
	if size == 0 {
		return nil
	}

	l := bits.Len(uint(size)) - 1
	if size != 1<<l {
		size = 1 << (l + 1)
	}
	x := bufioReaderPool(size).Get().(*bufio.Reader)

	x.Reset(r)

	return x
}

func PutBufioReader(b *bufio.Reader) {
	l := bits.Len(uint(b.Size())) - 1
	bufioReaderPool(1 << l).Put(b) //lint:ignore SA6002 ignore temporarily
}
