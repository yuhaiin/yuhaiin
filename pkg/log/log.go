package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
)

type Logger interface {
	Debug(string, ...any)
	Info(string, ...any)
	Warn(string, ...any)
	Error(string, ...any)
	Enabled(level slog.Level) bool
}

type LoggerAdvanced interface {
	Logger
	SetLevel(l slog.Level)
	SetOutput(io.Writer)
}

var DefaultLogger Logger = NewSLogger(1)
var OutputStderr bool = true

var writer *FileWriter
var mu sync.Mutex

func Set(config *protolog.Logcat, path string) {
	mu.Lock()
	defer mu.Unlock()

	al, ok := DefaultLogger.(LoggerAdvanced)
	if !ok {
		return
	}

	al.SetLevel(config.GetLevel().SLogLevel())

	if !config.GetSave() && writer != nil {
		al.SetOutput(os.Stdout)
		writer.Close()
		writer = nil
	}

	if config.GetSave() && writer == nil {
		writer = NewLogWriter(path)
		if OutputStderr {
			al.SetOutput(io.MultiWriter(writer, os.Stderr))
		} else {
			al.SetOutput(writer)
		}
	}
}

func Close() error {
	mu.Lock()
	defer mu.Unlock()
	if writer != nil {
		return writer.Close()
	}

	return nil
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

func Debug(msg string, v ...any) { DefaultLogger.Debug(msg, v...) }
func Info(msg string, v ...any)  { DefaultLogger.Info(msg, v...) }
func Warn(msg string, v ...any)  { DefaultLogger.Warn(msg, v...) }
func Error(msg string, v ...any) { DefaultLogger.Error(msg, v...) }
func Select(level slog.Level) LoggerOutput {
	if !DefaultLogger.Enabled(level) {
		return LoggerOutput{}
	}

	switch level {
	case slog.LevelDebug:
		return LoggerOutput{DefaultLogger.Debug}
	case slog.LevelInfo:
		return LoggerOutput{DefaultLogger.Info}
	case slog.LevelWarn:
		return LoggerOutput{DefaultLogger.Warn}
	case slog.LevelError:
		return LoggerOutput{DefaultLogger.Error}
	default:
		return LoggerOutput{DefaultLogger.Info}
	}
}

func IfErr(msg string, f func() error, ignoreErr ...error) {
	if err := f(); err != nil {
		DefaultLogger.Error(msg+" failed", "err", err)
	}
}

type slogger struct {
	slog.Handler
	depth int
}

func NewSLoggerWithHandler(h slog.Handler, depth int) *slogger {
	return &slogger{Handler: h, depth: 1 + depth}
}

func (l *slogger) Debug(msg string, v ...any)    { l.Output(1, slog.LevelDebug, msg, v...) }
func (l *slogger) Info(msg string, v ...any)     { l.Output(1, slog.LevelInfo, msg, v...) }
func (l *slogger) Warn(msg string, v ...any)     { l.Output(1, slog.LevelWarn, msg, v...) }
func (l *slogger) Error(msg string, v ...any)    { l.Output(1, slog.LevelError, msg, v...) }
func (l *slogger) Enabled(level slog.Level) bool { return l.Handler.Enabled(context.TODO(), level) }

func (l *slogger) Output(depth int, level slog.Level, msg string, v ...any) {
	if !l.Enabled(level) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(l.depth+depth+1, pcs[:]) // skip [Callers, Infof]
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(v...)

	_ = l.Handle(context.TODO(), r)
}

func NewSLogger(depth int) Logger {
	s := &slogLeveler{}
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

	dw := &dynamicWriter{os.Stdout}
	logger := NewSLoggerWithHandler(slog.NewTextHandler(dw, h), depth)

	return struct {
		*slogger
		*slogLeveler
		*dynamicWriter
	}{logger, s, dw}
}

type dynamicWriter struct {
	io.Writer
}

func (d *dynamicWriter) Write(p []byte) (n int, err error) {
	return d.Writer.Write(p)
}

func (l *dynamicWriter) SetOutput(w io.Writer) { l.Writer = w }

type slogLeveler struct{ atomic.Int32 }

func (s *slogLeveler) Level() slog.Level { return slog.Level(s.Load()) }

func (s *slogLeveler) SetLevel(l slog.Level) { s.Store(int32(l)) }
