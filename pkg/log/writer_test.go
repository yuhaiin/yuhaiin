package log

import (
	"os"
	"testing"
)

func TestRemove(t *testing.T) {
	f := &FileWriter{path: os.Getenv("HOME") + "/.config/yuhaiin/log/yuhaiin.log"}
	f.removeOldFile()
}
