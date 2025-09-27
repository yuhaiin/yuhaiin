package log

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
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

type Controller struct {
	writer *FileWriter
	path   string
	wmu    sync.RWMutex
}

func NewController() *Controller {
	return &Controller{}
}

func (l *Controller) Set(config *protolog.Logcat, path string) {
	leveler.Store(config.GetLevel().SLogLevel())

	if !config.GetSave() {
		_ = l.Close()
		return
	}

	l.wmu.Lock()
	defer l.wmu.Unlock()

	if l.writer != nil {
		return
	}

	l.path = path
	l.writer = NewLogWriter(path)
	var w io.Writer = l.writer
	if OutputStderr.Load() {
		w = io.MultiWriter(w, os.Stderr)
	}

	SetDefault(NewSLogger(w))
}

func (l *Controller) Close() error {
	SetDefault(NewSLogger(os.Stderr))

	l.wmu.Lock()
	w := l.writer
	l.writer = nil
	l.path = ""
	l.wmu.Unlock()

	if w != nil {
		return w.Close()
	}

	return nil
}

func (l *Controller) Tail(ctx context.Context, fn func(line []string)) error {
	f := newCycleFileReader(l.path)
	defer func() { _ = f.Close() }()

	var sign chan struct{}

	l.wmu.RLock()
	w := l.writer
	l.wmu.RUnlock()
	if w != nil {
		sign = w.NewCycleSign()
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
			_ = f.Close()
		case <-ticker.C:
			dump()
		}
	}
}
