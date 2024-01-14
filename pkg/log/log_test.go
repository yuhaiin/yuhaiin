package log

import (
	"errors"
	"log/slog"
	"testing"
)

func TestLog(t *testing.T) {
	Debug("debug")
	Info("source", slog.String("a", ""), slog.String("c", "d"))
	Output(0, slog.LevelError, "error")
	IfErr("test", func() error { return errors.New("log if err") })
}

func TestLogger(t *testing.T) {
	z := NewSLogger(0)

	z.Info("zzz")
	z.Output(0, slog.LevelInfo, "xxx")
}
