package log

import (
	"errors"
	"log/slog"
	"os"
	"testing"
)

func TestLog(t *testing.T) {
	Debug("debug")
	Info("source", slog.String("a", ""), slog.String("c", "d"))
	IfErr("test", func() error { return errors.New("log if err") })
	Select(slog.LevelInfo).Print("xxx")
}

func TestLogger(t *testing.T) {
	SetDefault(NewSLogger(os.Stderr))

	Info("zzz")
	leveler.Store(slog.LevelDebug)
	Debug("zzz")

	Select(slog.LevelInfo).Print("xxx")
}
