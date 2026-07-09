package log

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
)

const (
	logTailBatchSize        = 100
	logTailSubscriberBuffer = 128
)

type Controller struct {
	writer   *FileWriter
	path     string
	hub      *logHub
	wmu      sync.RWMutex
	streamMu sync.Mutex
}

func NewController() *Controller {
	return &Controller{hub: newLogHub()}
}

func SLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug", "verbose", "loglevel_debug", "loglevel_verbose":
		return slog.LevelDebug
	case "info", "loglevel_info":
		return slog.LevelInfo
	case "warning", "warn", "loglevel_warning":
		return slog.LevelWarn
	case "error", "fatal", "loglevel_error", "loglevel_fatal":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (l *Controller) Set(config contractsettings.Logcat, path string) {
	leveler.Store(SLogLevel(config.Level))

	if !config.Save {
		_ = l.Close()
		return
	}

	l.streamMu.Lock()
	defer l.streamMu.Unlock()

	l.wmu.Lock()
	defer l.wmu.Unlock()

	if l.writer != nil {
		return
	}

	if l.hub == nil {
		l.hub = newLogHub()
	}

	l.path = path
	l.writer = NewLogWriter(path)
	var w io.Writer = &liveLogWriter{
		file: l.writer,
		hub:  l.hub,
		gate: &l.streamMu,
	}
	if OutputStderr.Load() {
		w = io.MultiWriter(w, os.Stderr)
	}

	SetDefault(NewSLogger(w))
}

func (l *Controller) Close() error {
	SetDefault(NewSLogger(os.Stderr))

	l.streamMu.Lock()
	defer l.streamMu.Unlock()

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

func (l *Controller) Tail(ctx context.Context, fn func(line []string) error) error {
	l.wmu.RLock()
	w := l.writer
	path := l.path
	hub := l.hub
	l.wmu.RUnlock()

	if w == nil || hub == nil {
		return nil
	}

	l.streamMu.Lock()
	l.wmu.RLock()
	if l.writer != w || l.path != path {
		l.wmu.RUnlock()
		l.streamMu.Unlock()
		return nil
	}

	f, offset, err := openLogSnapshot(path)
	if err != nil {
		l.wmu.RUnlock()
		l.streamMu.Unlock()
		return err
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	id, ch := hub.subscribe()
	l.wmu.RUnlock()
	l.streamMu.Unlock()
	defer hub.unsubscribe(id)

	if err := tailFileSnapshot(ctx, f, offset, fn); err != nil {
		return err
	}
	if f != nil {
		_ = f.Close()
		f = nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case line := <-ch:
			if len(line) == 0 {
				continue
			}

			if err := fn(line); err != nil {
				return err
			}
		}
	}
}

func openLogSnapshot(path string) (*os.File, int64, error) {
	if path == "" {
		return nil, 0, nil
	}

	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}

	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}

	return f, stat.Size(), nil
}

func tailFileSnapshot(ctx context.Context, f *os.File, offset int64, fn func(line []string) error) error {
	if f == nil || offset <= 0 {
		return nil
	}
	reader := bufio.NewReader(io.LimitReader(f, offset))
	lines := make([]string, 0, logTailBatchSize)

	flush := func() error {
		if len(lines) == 0 {
			return nil
		}

		if err := fn(lines); err != nil {
			return err
		}

		lines = lines[:0]
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line, err := reader.ReadString('\n')
		if line != "" {
			lines = append(lines, trimLineBreak(line))
			if len(lines) >= logTailBatchSize {
				if err := flush(); err != nil {
					return err
				}
			}
		}

		if errors.Is(err, io.EOF) {
			return flush()
		}
		if err != nil {
			return err
		}
	}
}

func trimLineBreak(line string) string {
	line = strings.TrimSuffix(line, "\n")
	return strings.TrimSuffix(line, "\r")
}

type liveLogWriter struct {
	file    *FileWriter
	hub     *logHub
	gate    *sync.Mutex
	partial []byte
}

func (l *liveLogWriter) Write(p []byte) (n int, err error) {
	l.gate.Lock()
	defer l.gate.Unlock()

	n, err = l.file.Write(p)
	if n > 0 {
		l.publish(p[:n])
	}

	return n, err
}

func (l *liveLogWriter) publish(p []byte) {
	lines := make([]string, 0, bytes.Count(p, []byte{'\n'}))

	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			l.partial = append(l.partial, p...)
			break
		}

		line := p[:i]
		if len(l.partial) > 0 {
			l.partial = append(l.partial, line...)
			lines = append(lines, trimLineBreak(string(l.partial)))
			l.partial = l.partial[:0]
		} else {
			lines = append(lines, trimLineBreak(string(line)))
		}

		p = p[i+1:]
	}

	if len(lines) > 0 {
		l.hub.publish(lines)
	}
}

type logHub struct {
	mu   sync.Mutex
	next uint64
	subs map[uint64]chan []string
}

func newLogHub() *logHub {
	return &logHub{subs: map[uint64]chan []string{}}
}

func (l *logHub) subscribe() (uint64, <-chan []string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.subs == nil {
		l.subs = map[uint64]chan []string{}
	}

	id := l.next
	l.next++
	ch := make(chan []string, logTailSubscriberBuffer)
	l.subs[id] = ch
	return id, ch
}

func (l *logHub) unsubscribe(id uint64) {
	l.mu.Lock()
	delete(l.subs, id)
	l.mu.Unlock()
}

func (l *logHub) publish(lines []string) {
	l.mu.Lock()
	subscribers := make([]chan []string, 0, len(l.subs))
	for _, ch := range l.subs {
		subscribers = append(subscribers, ch)
	}
	l.mu.Unlock()

	for _, ch := range subscribers {
		select {
		case ch <- lines:
		default:
		}
	}
}
