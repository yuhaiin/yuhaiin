package log

import (
	"testing"

	"golang.org/x/exp/slog"
)

func TestLog(t *testing.T) {
	Debugln("debug")
	Infoln("info")
	Output(0, slog.LevelError, "error")
}

func TestLogger(t *testing.T) {
	z := NewLogger(0)

	z.Infoln("zzz")
}
