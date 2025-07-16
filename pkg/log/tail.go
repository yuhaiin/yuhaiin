package log

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type cycleFileReader struct {
	path string
	f    *os.File
	mu   sync.Mutex
}

func newCycleFileReader(path string) *cycleFileReader {
	return &cycleFileReader{
		path: path,
	}
}

func (c *cycleFileReader) init() (io.Reader, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.f != nil {
		return c.f, nil
	}

	f, err := os.Open(c.path)
	if err != nil {
		return nil, err
	}

	c.f = f
	return c, nil
}

func (c *cycleFileReader) Read(p []byte) (n int, err error) {
	f, err := c.init()
	if err != nil {
		return 0, err
	}

	return f.Read(p)
}

func (c *cycleFileReader) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.f == nil {
		return nil
	}

	err := c.f.Close()
	c.f = nil
	return err
}

func Tail(ctx context.Context, path string, fn func(line []string)) error {
	f := newCycleFileReader(path)
	defer f.Close()

	var sign chan struct{}

	mu.RLock()
	w := writer
	mu.RUnlock()
	if w != nil {
		sign = writer.NewCycleSign()
		defer w.RemoveCycleSign(sign)
	} else {
		sign = make(chan struct{})
	}

	scan := pool.GetBufioReader(f, 1024)
	defer pool.PutBufioReader(scan)

	var ret []string

	dump := func() {
		for {
			ret = ret[:0]

			for range 100 {
				line, _, err := scan.ReadLine()
				if err != nil {
					break
				}

				ret = append(ret, string(line))
			}

			if len(ret) == 0 {
				break
			}

			fn(ret)
		}
	}

	dump()

	ticker := time.NewTicker(time.Second)

	for {
		select {
		case <-ctx.Done():
			return nil
		case sign <- struct{}{}:
			f.Close()
		case <-ticker.C:
			dump()
		}
	}
}
