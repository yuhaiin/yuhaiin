package log

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
)

var (
	defaultLogger slog.Handler = NewSLogger(os.Stderr)
	OutputStderr               = atomicx.NewValue(true)
	leveler                    = atomicx.NewValue(slog.LevelInfo)
	mu            sync.RWMutex
)

func Default() slog.Handler {
	mu.RLock()
	defer mu.RUnlock()
	return defaultLogger
}

func SetDefault(logger slog.Handler) {
	mu.Lock()
	defer mu.Unlock()
	defaultLogger = logger
}

type LoggerOutput struct {
	log func(msg string, v ...any)
}

func (f LoggerOutput) Print(msg string, v ...any) {
	if f.log == nil {
		return
	}
	f.log(msg, v...)
}

func (f LoggerOutput) PrintFunc(msg string, ff func() []any) {
	if f.log == nil {
		return
	}
	f.log(msg, ff()...)
}

func Debug(msg string, v ...any) {
	Output(Default(), 2, slog.LevelDebug, msg, v...)
}

func Info(msg string, v ...any) {
	Output(Default(), 2, slog.LevelInfo, msg, v...)
}

func Warn(msg string, v ...any) {
	Output(Default(), 2, slog.LevelWarn, msg, v...)
}

func Error(msg string, v ...any) {
	Output(Default(), 2, slog.LevelError, msg, v...)
}

func InfoFormat(format string, v ...any) {
	Output(Default(), 2, slog.LevelInfo, fmt.Sprintf(format, v...))
}

func Select(level slog.Level) LoggerOutput {
	if !Default().Enabled(context.TODO(), level) {
		return LoggerOutput{}
	}

	return LoggerOutput{
		log: func(msg string, v ...any) {
			Output(Default(), 3, level, msg, v...)
		},
	}
}

func IfErr(msg string, f func() error, ignoreErr ...error) {
	if err := f(); err != nil {
		for _, ignore := range ignoreErr {
			if errors.Is(err, ignore) {
				return
			}
		}
		Output(Default(), 2, slog.LevelError, msg+" failed", "err", err)
	}
}

func Output(handler slog.Handler, depth int, level slog.Level, msg string, v ...any) {
	if !handler.Enabled(context.TODO(), level) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(depth+1, pcs[:]) // skip [Callers, Infof]
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(v...)

	if err := handler.Handle(context.TODO(), r); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "log output failed:", err)
	}
}

type slogLeveler struct{}

func (slogLeveler) Level() slog.Level { return leveler.Load() }

func NewSLogger(w io.Writer) slog.Handler {
	h := &slog.HandlerOptions{
		AddSource: true,
		Level:     slogLeveler{},
		ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			switch attr.Key {
			// Remove time.
			// case slog.TimeKey:
			// 	if len(groups) == 0 {
			// 		a.Key = ""
			// 	}

			// Remove the directory from the source's filename.
			case slog.SourceKey:
				source, ok := attr.Value.Any().(*slog.Source)
				if ok {
					source.Function = ""
					source.File = filepath.Base(source.File)
					attr.Value = slog.AnyValue(source)
				}
				return attr

			default:
				return attr
			}
		},
	}

	return slog.NewTextHandler(w, h)
}
