package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

type cycleFileReader struct {
	f    *os.File
	path string
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

func SLogLevel(l config.LogLevel) slog.Level {
	switch l {
	case config.LogLevel_debug, config.LogLevel_verbose:
		return slog.LevelDebug
	case config.LogLevel_info:
		return slog.LevelInfo
	case config.LogLevel_warning:
		return slog.LevelWarn
	case config.LogLevel_error, config.LogLevel_fatal:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (l *Controller) Set(config *config.Logcat, path string) {
	leveler.Store(SLogLevel(config.GetLevel()))

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

	l.wmu.RLock()
	w := l.writer
	l.wmu.RUnlock()

	if w == nil {
		return nil
	}

	fileCount := w.NewFileCount()

	scan := pool.GetBufioReader(f, 1024)
	defer pool.PutBufioReader(scan)

	dump := func() {
		if fileCount != w.NewFileCount() {
			_ = f.Close()
			fileCount = w.NewFileCount()
			return
		}

		var ret []string

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
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			dump()
		}
	}
}
