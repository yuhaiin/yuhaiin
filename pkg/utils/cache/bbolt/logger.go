package bbolt

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"go.etcd.io/bbolt"
)

var _ bbolt.Logger = BBoltDBLogger{}

type BBoltDBLogger struct{}

func (l BBoltDBLogger) Debug(v ...any) {
	log.DefaultLogger.Debug(fmt.Sprint(v...))
}

func (l BBoltDBLogger) Debugf(format string, v ...any) {
	log.DefaultLogger.Debug(fmt.Sprintf(format, v...))
}

func (l BBoltDBLogger) Error(v ...any) {
	log.DefaultLogger.Error(fmt.Sprint(v...))
}

func (l BBoltDBLogger) Errorf(format string, v ...any) {
	log.DefaultLogger.Error(fmt.Sprintf(format, v...))
}

func (l BBoltDBLogger) Info(v ...any) {
	log.DefaultLogger.Info(fmt.Sprint(v...))
}

func (l BBoltDBLogger) Infof(format string, v ...any) {
	log.DefaultLogger.Info(fmt.Sprintf(format, v...))
}

func (l BBoltDBLogger) Warning(v ...any) {
	log.DefaultLogger.Warn(fmt.Sprint(v...))
}

func (l BBoltDBLogger) Warningf(format string, v ...any) {
	log.DefaultLogger.Warn(fmt.Sprintf(format, v...))
}

func (l BBoltDBLogger) Fatal(v ...any) {
	log.DefaultLogger.Error(fmt.Sprint(v...))
}

func (l BBoltDBLogger) Fatalf(format string, v ...any) {
	log.DefaultLogger.Error(fmt.Sprintf(format, v...))
}

func (l BBoltDBLogger) Panic(v ...any) {
	log.DefaultLogger.Error(fmt.Sprint(v...))
}

func (l BBoltDBLogger) Panicf(format string, v ...any) {
	log.DefaultLogger.Error(fmt.Sprintf(format, v...))
}
