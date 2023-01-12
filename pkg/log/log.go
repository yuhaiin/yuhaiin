package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	protolog "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
)

//go:generate protoc --go_out=. --go_opt=paths=source_relative log.proto
type Logger interface {
	SetLevel(protolog.LogLevel)
	IsOutput(protolog.LogLevel) bool
	Verbosef(string, ...any)
	Verboseln(...any)
	Debugf(string, ...any)
	Debugln(...any)
	Infof(string, ...any)
	Infoln(...any)
	Warningf(string, ...any)
	Warningln(...any)
	Errorf(string, ...any)
	Errorln(...any)
	Output(depth int, lev protolog.LogLevel, format string, v ...any)
	SetOutput(io.Writer)
}

var DefaultLogger Logger = NewLogger(1)

var writer *FileWriter
var lock sync.Mutex

func Set(config *protolog.Logcat, path string) {
	lock.Lock()
	defer lock.Unlock()
	DefaultLogger.SetLevel(config.Level)
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
	lock.Lock()
	defer lock.Unlock()
	if writer != nil {
		writer.Close()
	}
	return nil
}

func SetLevel(l protolog.LogLevel)      { DefaultLogger.SetLevel(l) }
func IsOutput(l protolog.LogLevel) bool { return DefaultLogger.IsOutput(l) }
func Verbosef(format string, v ...any)  { DefaultLogger.Verbosef(format, v...) }
func Verboseln(v ...any)                { DefaultLogger.Verboseln(v...) }
func Debugf(format string, v ...any)    { DefaultLogger.Debugf(format, v...) }
func Debugln(v ...any)                  { DefaultLogger.Debugln(v...) }
func Infof(format string, v ...any)     { DefaultLogger.Infof(format, v...) }
func Infoln(v ...any)                   { DefaultLogger.Infoln(v...) }
func Warningf(format string, v ...any)  { DefaultLogger.Warningf(format, v...) }
func Warningln(v ...any)                { DefaultLogger.Warningln(v...) }
func Errorf(format string, v ...any)    { DefaultLogger.Errorf(format, v...) }
func Errorln(v ...any)                  { DefaultLogger.Errorln(v...) }
func Output(depth int, lev protolog.LogLevel, format string, v ...any) {
	DefaultLogger.Output(depth+1, lev, format, v...)
}

type logger struct {
	level protolog.LogLevel
	depth int32
	log   *log.Logger
}

func NewLogger(depth int32) *logger {
	return &logger{
		log:   log.New(os.Stdout, "", log.Lshortfile|log.LstdFlags),
		level: protolog.LogLevel_info,
		depth: 2 + depth,
	}
}

func (l *logger) SetLevel(z protolog.LogLevel)     { l.level = z }
func (l logger) IsOutput(z protolog.LogLevel) bool { return l.level <= z }

func (l *logger) Verbosef(format string, v ...any) {
	if l.level <= protolog.LogLevel_verbose {
		l.log.Output(int(l.depth), fmt.Sprintf(format, v...))
	}
}

func (l *logger) Verboseln(v ...any) {
	if l.level <= protolog.LogLevel_verbose {
		l.log.Output(int(l.depth), fmt.Sprintln(v...))
	}
}
func (l *logger) Debugf(format string, v ...any) {
	if l.level <= protolog.LogLevel_debug {
		l.log.Output(int(l.depth), fmt.Sprintf(format, v...))
	}
}

func (l *logger) Debugln(v ...any) {
	if l.level <= protolog.LogLevel_debug {
		l.log.Output(int(l.depth), fmt.Sprintln(v...))
	}
}

func (l *logger) Infof(format string, v ...any) {
	if l.level <= protolog.LogLevel_info {
		l.log.Output(int(l.depth), fmt.Sprintf(format, v...))
	}
}

func (l *logger) Infoln(v ...any) {
	if l.level <= protolog.LogLevel_info {
		l.log.Output(int(l.depth), fmt.Sprintln(v...))
	}
}

func (l *logger) Warningf(format string, v ...any) {
	if l.level <= protolog.LogLevel_warning {
		l.log.Output(int(l.depth), fmt.Sprintf(format, v...))
	}
}

func (l *logger) Warningln(v ...any) {
	if l.level <= protolog.LogLevel_warning {
		l.log.Output(int(l.depth), fmt.Sprintln(v...))
	}
}

func (l *logger) Errorf(format string, v ...any) {
	if l.level <= protolog.LogLevel_error {
		l.log.Output(int(l.depth), fmt.Sprintf(format, v...))
	}
}

func (l *logger) Errorln(v ...any) {
	if l.level <= protolog.LogLevel_error {
		l.log.Output(int(l.depth), fmt.Sprintln(v...))
	}
}

func (l *logger) Output(depth int, lev protolog.LogLevel, format string, v ...any) {
	if l.level <= lev {
		l.log.Output(depth+1, fmt.Sprintf(format, v...))
	}
}

func (l *logger) SetOutput(w io.Writer) { l.log.SetOutput(w) }
