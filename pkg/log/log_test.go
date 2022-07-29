package log

import (
	"log"
	"testing"
)

func TestLog(t *testing.T) {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	Debugln("debug")
	Infoln("info")
}
