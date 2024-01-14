package log

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative log.proto

type Logger interface {
	Debug(string, ...any)
	Info(string, ...any)
	Warn(string, ...any)
	Error(string, ...any)
	Output(depth int, lev slog.Level, msg string, v ...any)
}

var DefaultLogger Logger = NewSLogger(1)

var writer *FileWriter
var mu sync.Mutex

func Set(config *protolog.Logcat, path string) {
	mu.Lock()
	defer mu.Unlock()
	if logger, ok := DefaultLogger.(interface{ SetLevel(l slog.Level) }); ok {
		logger.SetLevel(config.Level.SLogLevel())
	}

	logger, ok := DefaultLogger.(interface{ SetOutput(io.Writer) })
	if !ok {
		return
	}

	if !config.Save && writer != nil {
		logger.SetOutput(os.Stdout)
		writer.Close()
		writer = nil
	}

	if config.Save && writer == nil {
		writer = NewLogWriter(path)
		logger.SetOutput(io.MultiWriter(os.Stderr, writer))
	}
}

func Close() error {
	mu.Lock()
	defer mu.Unlock()
	if writer != nil {
		writer.Close()
	}
	return nil
}

func Debug(msg string, v ...any) { DefaultLogger.Debug(msg, v...) }
func Info(msg string, v ...any)  { DefaultLogger.Info(msg, v...) }
func Warn(msg string, v ...any)  { DefaultLogger.Warn(msg, v...) }
func Error(msg string, v ...any) { DefaultLogger.Error(msg, v...) }
func Output(depth int, lev slog.Level, format string, v ...any) {
	DefaultLogger.Output(depth, lev, format, v...)
}
func IfErr(msg string, f func() error, ignoreErr ...error) {
	if err := f(); err != nil {
		for _, ignore := range ignoreErr {
			if errors.Is(err, ignore) {
				return
			}
		}

		DefaultLogger.Error(msg+" failed", "err", err)
	}
}

type slogger struct {
	depth int

	io.Writer
	level slog.Level
	*slog.Logger
}

func NewSLogger(depth int) Logger {
	s := &slogger{
		Writer: os.Stdout,
		depth:  1 + depth,
	}
	h := &slog.HandlerOptions{
		AddSource: true,
		Level:     s,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove time.
			// if a.Key == slog.TimeKey && len(groups) == 0 {
			// a.Key = ""
			// }

			// Remove the directory from the source's filename.
			if a.Key == slog.SourceKey {
				source, ok := a.Value.Any().(*slog.Source)
				if ok {
					source.Function = ""
					source.File = filepath.Base(source.File)
					a.Value = slog.AnyValue(source)
				}
			}

			return a
		},
	}

	s.Logger = slog.New(slog.NewTextHandler(s, h))
	return s

}
func (l *slogger) SetLevel(z slog.Level)      { l.level = z }
func (l *slogger) Level() slog.Level          { return l.level }
func (l *slogger) Debug(msg string, v ...any) { l.Output(1, slog.LevelDebug, msg, v...) }
func (l *slogger) Info(msg string, v ...any)  { l.Output(1, slog.LevelInfo, msg, v...) }
func (l *slogger) Warn(msg string, v ...any)  { l.Output(1, slog.LevelWarn, msg, v...) }
func (l *slogger) Error(msg string, v ...any) { l.Output(1, slog.LevelError, msg, v...) }
func (l *slogger) Output(depth int, level slog.Level, msg string, v ...any) {
	ctx := context.Background()

	if !l.Enabled(ctx, level) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(l.depth+depth+1, pcs[:]) // skip [Callers, Infof]
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(v...)

	_ = l.Logger.Handler().Handle(ctx, r)
}

func (l *slogger) SetOutput(w io.Writer) { l.Writer = w }
