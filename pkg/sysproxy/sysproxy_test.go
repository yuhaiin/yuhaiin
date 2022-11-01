package sysproxy

import (
	"os"
	"os/exec"
	"testing"
)

func TestXDG(t *testing.T) {
	t.Log(os.Getenv("XDG_SESSION_DESKTOP"))
	t.Log(os.Getenv("XDG_SESSION_DESKTOP") == "KDE")
}

func TestLookUP(t *testing.T) {
	t.Log(exec.LookPath("gsettings"))
	t.Log(exec.LookPath("kwriteconfig5"))
}
