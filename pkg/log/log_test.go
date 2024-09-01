package log

import (
	"errors"
	"log/slog"
	"testing"
)

func TestLog(t *testing.T) {
	Debug("debug")
	Info("source", slog.String("a", ""), slog.String("c", "d"))
	IfErr("test", func() error { return errors.New("log if err") })
	Select(slog.LevelInfo).Print("xxx")
}

func TestLogger(t *testing.T) {
	z := NewSLogger(0)

	z.Info("zzz")
	z.(interface{ SetLevel(l slog.Level) }).SetLevel(slog.LevelDebug)
	z.Debug("zzz")
}
