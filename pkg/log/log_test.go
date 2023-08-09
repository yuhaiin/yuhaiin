package log

import (
	"testing"

	"log/slog"
)

func TestLog(t *testing.T) {
	Debug("debug")
	Info("source", slog.String("a", ""), slog.String("c", "d"))
	Output(0, slog.LevelError, "error")
}

func TestLogger(t *testing.T) {
	z := NewSLogger(0)

	z.Info("zzz")
}
