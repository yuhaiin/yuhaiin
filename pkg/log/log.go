package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"

	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
	"golang.org/x/exp/slog"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative log.proto
type Logger interface {
	SetLevel(slog.Level)

	Debug(string, ...any)
	Debugf(string, ...any)
	Debugln(...any)
	Info(string, ...any)
	Infof(string, ...any)
	Infoln(...any)
	Warn(string, ...any)
	Warningf(string, ...any)
	Warningln(...any)
	Error(string, ...any)
	Errorf(string, ...any)
	Errorln(...any)
	Output(depth int, lev slog.Level, format string, v ...any)
	SetOutput(io.Writer)
}

var DefaultLogger Logger = NewSLogger(1)

var writer *FileWriter
var mu sync.Mutex

func Set(config *protolog.Logcat, path string) {
	mu.Lock()
	defer mu.Unlock()
	DefaultLogger.SetLevel(config.Level.SLogLevel())
	if !config.Save && writer != nil {
		DefaultLogger.SetOutput(os.Stdout)
		writer.Close()
		writer = nil
	}

	if config.Save && writer == nil {
		writer = NewLogWriter(path)
		DefaultLogger.SetOutput(io.MultiWriter(os.Stdout, writer))
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

func SetLevel(l slog.Level)            { DefaultLogger.SetLevel(l) }
func Debug(msg string, v ...any)       { DefaultLogger.Debug(msg, v...) }
func Debugf(format string, v ...any)   { DefaultLogger.Debugf(format, v...) }
func Debugln(v ...any)                 { DefaultLogger.Debugln(v...) }
func Infof(format string, v ...any)    { DefaultLogger.Infof(format, v...) }
func Infoln(v ...any)                  { DefaultLogger.Infoln(v...) }
func Warningf(format string, v ...any) { DefaultLogger.Warningf(format, v...) }
func Warningln(v ...any)               { DefaultLogger.Warningln(v...) }
func Errorf(format string, v ...any)   { DefaultLogger.Errorf(format, v...) }
func Errorln(v ...any)                 { DefaultLogger.Errorln(v...) }
func Output(depth int, lev slog.Level, format string, v ...any) {
	DefaultLogger.Output(depth+1, lev, format, v...)
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
	h := slog.HandlerOptions{
		AddSource: true,
		Level:     s,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				v := a.Value.String()
				if i := strings.LastIndexByte(v, '/'); i != -1 {
					a.Value = slog.StringValue(v[i+1:])
				}
			}
			return a
		},
	}

	s.Logger = slog.New(h.NewTextHandler(s))

	return s

}
func (l *slogger) SetLevel(z slog.Level) { l.level = z }
func (l *slogger) Level() slog.Level     { return l.level }

func (l *slogger) Debug(msg string, v ...any) {
	l.Logger.LogDepth(l.depth, slog.LevelDebug, msg, v...)
}

func (l *slogger) Debugf(format string, v ...any) {
	if l.level <= slog.LevelDebug {
		l.Logger.LogDepth(l.depth, slog.LevelDebug, fmt.Sprintf(format, v...))
	}
}

func (l *slogger) Debugln(v ...any) {
	if l.level <= slog.LevelDebug {
		l.Logger.LogDepth(l.depth, slog.LevelDebug, fmt.Sprint(v...))
	}
}

func (l *slogger) Info(msg string, v ...any) {
	l.Logger.LogDepth(l.depth, slog.LevelInfo, msg, v...)
}

func (l *slogger) Infof(format string, v ...any) {
	if l.level <= slog.LevelInfo {
		l.Logger.LogDepth(l.depth, slog.LevelInfo, fmt.Sprintf(format, v...))
	}
}

func (l *slogger) Infoln(v ...any) {
	if l.level <= slog.LevelInfo {
		l.Logger.LogDepth(l.depth, slog.LevelInfo, fmt.Sprint(v...))
	}
}

func (l *slogger) Warn(msg string, v ...any) {
	l.Logger.LogDepth(l.depth, slog.LevelWarn, msg, v...)
}

func (l *slogger) Warningf(format string, v ...any) {
	if l.level <= slog.LevelWarn {
		l.Logger.LogDepth(l.depth, slog.LevelWarn, fmt.Sprintf(format, v...))
	}
}

func (l *slogger) Warningln(v ...any) {
	if l.level <= slog.LevelWarn {
		l.Logger.LogDepth(l.depth, slog.LevelWarn, fmt.Sprint(v...))
	}
}

func (l *slogger) Error(msg string, v ...any) {
	l.Logger.LogDepth(l.depth, slog.LevelError, msg, v...)
}

func (l *slogger) Errorf(format string, v ...any) {
	if l.level <= slog.LevelError {
		l.Logger.LogDepth(l.depth, slog.LevelError, fmt.Sprintf(format, v...))
	}
}

func (l *slogger) Errorln(v ...any) {
	if l.level <= slog.LevelError {
		l.Logger.LogDepth(l.depth, slog.LevelError, fmt.Sprint(v...))
	}
}

func (l *slogger) Output(depth int, lev slog.Level, msg string, v ...any) {
	l.Logger.LogDepth(depth+1, lev, msg, v...)
}

func (l *slogger) SetOutput(w io.Writer) { l.Writer = w }

type logger struct {
	level slog.Level
	depth int32
	log   *log.Logger
}

func NewLogger(depth int32) *logger {
	return &logger{
		log:   log.New(os.Stdout, "", log.Lshortfile|log.LstdFlags),
		level: slog.LevelInfo,
		depth: 2 + depth,
	}
}

func (l *logger) SetLevel(z slog.Level) { l.level = z }
func (l *logger) Level() slog.Level     { return slog.LevelDebug }

func (l *logger) Debugf(format string, v ...any) {
	if l.level <= slog.LevelDebug {
		l.log.Output(int(l.depth), fmt.Sprintf(format, v...))
	}
}

func (l *logger) Debugln(v ...any) {
	if l.level <= slog.LevelDebug {
		l.log.Output(int(l.depth), fmt.Sprintln(v...))
	}
}

func (l *logger) Infof(format string, v ...any) {
	if l.level <= slog.LevelInfo {
		l.log.Output(int(l.depth), fmt.Sprintf(format, v...))
	}
}

func (l *logger) Infoln(v ...any) {
	if l.level <= slog.LevelInfo {
		l.log.Output(int(l.depth), fmt.Sprintln(v...))
	}
}

func (l *logger) Warningf(format string, v ...any) {
	if l.level <= slog.LevelWarn {
		l.log.Output(int(l.depth), fmt.Sprintf(format, v...))
	}
}

func (l *logger) Warningln(v ...any) {
	if l.level <= slog.LevelWarn {
		l.log.Output(int(l.depth), fmt.Sprintln(v...))
	}
}

func (l *logger) Errorf(format string, v ...any) {
	if l.level <= slog.LevelError {
		l.log.Output(int(l.depth), fmt.Sprintf(format, v...))
	}
}

func (l *logger) Errorln(v ...any) {
	if l.level <= slog.LevelError {
		l.log.Output(int(l.depth), fmt.Sprintln(v...))
	}
}

func (l *logger) Output(depth int, lev slog.Level, format string, v ...any) {
	if l.level <= lev {
		l.log.Output(depth+1, fmt.Sprintf(format, v...))
	}
}

func (l *logger) SetOutput(w io.Writer) { l.log.SetOutput(w) }
