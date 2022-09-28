package log

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
)

func TestLog(t *testing.T) {
	Debugln("debug")
	Infoln("info")
	Output(1, log.LogLevel_error, "error")
}

func TestLogger(t *testing.T) {
	z := NewLogger(0)

	z.Infoln("zzz")
}
