package log

import (
	"log"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func TestLog(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	Debugln("debug")
	Infoln("info")
	Output(1, config.Logcat_error, "error")
}
