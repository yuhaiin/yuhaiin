package bbolt

import (
	"fmt"
	"log/slog"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"go.etcd.io/bbolt"
)

var _ bbolt.Logger = BBoltDBLogger{}

type BBoltDBLogger struct{}

func (l BBoltDBLogger) Debug(v ...any) {
	log.Output(log.Default(), 2, slog.LevelDebug, fmt.Sprint(v...))
}

func (l BBoltDBLogger) Debugf(format string, v ...any) {
	log.Output(log.Default(), 2, slog.LevelDebug, fmt.Sprintf(format, v...))
}

func (l BBoltDBLogger) Error(v ...any) {
	log.Output(log.Default(), 2, slog.LevelError, fmt.Sprint(v...))
}

func (l BBoltDBLogger) Errorf(format string, v ...any) {
	log.Output(log.Default(), 2, slog.LevelError, fmt.Sprintf(format, v...))
}

func (l BBoltDBLogger) Info(v ...any) {
	log.Output(log.Default(), 2, slog.LevelInfo, fmt.Sprint(v...))
}

func (l BBoltDBLogger) Infof(format string, v ...any) {
	log.Output(log.Default(), 2, slog.LevelInfo, fmt.Sprintf(format, v...))
}

func (l BBoltDBLogger) Warning(v ...any) {
	log.Output(log.Default(), 2, slog.LevelWarn, fmt.Sprint(v...))
}

func (l BBoltDBLogger) Warningf(format string, v ...any) {
	log.Output(log.Default(), 2, slog.LevelWarn, fmt.Sprintf(format, v...))
}

func (l BBoltDBLogger) Fatal(v ...any) {
	log.Output(log.Default(), 2, slog.LevelError, fmt.Sprint(v...))
}

func (l BBoltDBLogger) Fatalf(format string, v ...any) {
	log.Output(log.Default(), 2, slog.LevelError, fmt.Sprintf(format, v...))
}

func (l BBoltDBLogger) Panic(v ...any) {
	log.Output(log.Default(), 2, slog.LevelError, fmt.Sprint(v...))
}

func (l BBoltDBLogger) Panicf(format string, v ...any) {
	log.Output(log.Default(), 2, slog.LevelError, fmt.Sprintf(format, v...))
}
