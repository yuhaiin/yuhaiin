package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

var writer *FileWriter
var lock sync.Mutex

func Set(config *config.Logcat, path string) {
	lock.Lock()
	defer lock.Unlock()
	SetLevel(config.Level)
	if config.Save && writer != nil {
		log.SetOutput(os.Stdout)
		writer.Close()
		writer = nil
	}

	if config.Save && writer == nil {
		writer = NewLogWriter(path)
		log.SetOutput(io.MultiWriter(os.Stdout, writer))
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

var level = config.Logcat_debug

func SetLevel(l config.LogcatLogLevel)      { level = l }
func IsOutput(l config.LogcatLogLevel) bool { return level <= l }

func Debugf(format string, v ...any) {
	if level <= config.Logcat_debug {
		log.Output(2, fmt.Sprintf(format, v...))
	}
}

func Debugln(v ...any) {
	if level <= config.Logcat_debug {
		log.Output(2, fmt.Sprintln(v...))
	}
}

func Infof(format string, v ...any) {
	if level <= config.Logcat_info {
		log.Output(2, fmt.Sprintf(format, v...))
	}
}

func Infoln(v ...any) {
	if level <= config.Logcat_info {
		log.Output(2, fmt.Sprintln(v...))
	}
}

func Warningf(format string, v ...any) {
	if level <= config.Logcat_warning {
		log.Output(2, fmt.Sprintf(format, v...))
	}
}

func Warningln(v ...any) {
	if level <= config.Logcat_warning {
		log.Output(2, fmt.Sprintln(v...))
	}
}

func Errorf(format string, v ...any) {
	if level <= config.Logcat_error {
		log.Output(2, fmt.Sprintf(format, v...))
	}
}

func Errorln(v ...any) {
	if level <= config.Logcat_error {
		log.Output(2, fmt.Sprintln(v...))
	}
}
