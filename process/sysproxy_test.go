package process

import (
	"os"
	"os/exec"
	"testing"
)

func TestSet(t *testing.T) {
	t.Log(exec.Command("kwriteconfig5", "--file", os.Getenv("HOME")+"/.config/kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1").Run())
}

func TestUnsetConFig(t *testing.T) {
	UnsetSysProxy()
}
func TestSetConFig(t *testing.T) {
	SetSysProxy()
}

func TestXDG_(t *testing.T) {
	t.Log(os.Getenv("XDG_SESSION_DESKTOP"))
	t.Log(os.Getenv("XDG_SESSION_DESKTOP") == "KDE")
}
