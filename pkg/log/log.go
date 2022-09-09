package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

type Logger interface {
	SetLevel(config.LogcatLogLevel)
	IsOutput(config.LogcatLogLevel) bool
	Debugf(string, ...any)
	Debugln(...any)
	Infof(string, ...any)
	Infoln(...any)
	Warningf(string, ...any)
	Warningln(...any)
	Errorf(string, ...any)
	Errorln(...any)
	Output(depth int, lev config.LogcatLogLevel, format string, v ...any)
	SetOutput(io.Writer)
}

var DefaultLogger Logger = NewLogger(1)

var writer *FileWriter
var lock sync.Mutex

func Set(config *config.Logcat, path string) {
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

func SetLevel(l config.LogcatLogLevel)      { DefaultLogger.SetLevel(l) }
func IsOutput(l config.LogcatLogLevel) bool { return DefaultLogger.IsOutput(l) }
func Debugf(format string, v ...any)        { DefaultLogger.Debugf(format, v...) }
func Debugln(v ...any)                      { DefaultLogger.Debugln(v...) }
func Infof(format string, v ...any)         { DefaultLogger.Infof(format, v...) }
func Infoln(v ...any)                       { DefaultLogger.Infoln(v...) }
func Warningf(format string, v ...any)      { DefaultLogger.Warningf(format, v...) }
func Warningln(v ...any)                    { DefaultLogger.Warningln(v...) }
func Errorf(format string, v ...any)        { DefaultLogger.Errorf(format, v...) }
func Errorln(v ...any)                      { DefaultLogger.Errorln(v...) }
func Output(depth int, lev config.LogcatLogLevel, format string, v ...any) {
	DefaultLogger.Output(depth+1, lev, format, v...)
}

type logger struct {
	log   *log.Logger
	level config.LogcatLogLevel
	depth int
}

func NewLogger(depth int) *logger {
	return &logger{
		log:   log.New(os.Stdout, "", log.Lshortfile|log.LstdFlags),
		level: config.Logcat_info,
		depth: 2 + depth,
	}
}

func (l *logger) SetLevel(z config.LogcatLogLevel)     { l.level = z }
func (l logger) IsOutput(z config.LogcatLogLevel) bool { return l.level <= z }

func (l *logger) Debugf(format string, v ...any) {
	if l.level <= config.Logcat_debug {
		l.log.Output(l.depth, fmt.Sprintf(format, v...))
	}
}

func (l *logger) Debugln(v ...any) {
	if l.level <= config.Logcat_debug {
		l.log.Output(l.depth, fmt.Sprintln(v...))
	}
}

func (l *logger) Infof(format string, v ...any) {
	if l.level <= config.Logcat_info {
		l.log.Output(l.depth, fmt.Sprintf(format, v...))
	}
}

func (l *logger) Infoln(v ...any) {
	if l.level <= config.Logcat_info {
		l.log.Output(l.depth, fmt.Sprintln(v...))
	}
}

func (l *logger) Warningf(format string, v ...any) {
	if l.level <= config.Logcat_warning {
		l.log.Output(l.depth, fmt.Sprintf(format, v...))
	}
}

func (l *logger) Warningln(v ...any) {
	if l.level <= config.Logcat_warning {
		l.log.Output(l.depth, fmt.Sprintln(v...))
	}
}

func (l *logger) Errorf(format string, v ...any) {
	if l.level <= config.Logcat_error {
		l.log.Output(l.depth, fmt.Sprintf(format, v...))
	}
}

func (l *logger) Errorln(v ...any) {
	if l.level <= config.Logcat_error {
		l.log.Output(l.depth, fmt.Sprintln(v...))
	}
}

func (l *logger) Output(depth int, lev config.LogcatLogLevel, format string, v ...any) {
	if l.level <= lev {
		l.log.Output(depth+1, fmt.Sprintf(format, v...))
	}
}

func (l *logger) SetOutput(w io.Writer) { l.log.SetOutput(w) }
