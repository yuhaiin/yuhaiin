package sysproxy

import (
	"net"
	"net/url"
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
	SetSysProxy("127.0.0.1:8188", "127.0.0.1:1080")
}

func TestXDG_(t *testing.T) {
	t.Log(os.Getenv("XDG_SESSION_DESKTOP"))
	t.Log(os.Getenv("XDG_SESSION_DESKTOP") == "KDE")
}

func TestLookUP(t *testing.T) {
	t.Log(exec.LookPath("gsettings"))
	t.Log(exec.LookPath("kwriteconfig5"))
}

func TestAddress(t *testing.T) {
	urls, _ := url.Parse("//[::]:1080")
	t.Log(urls.Hostname())
	t.Log(net.ParseIP("::1").String())
}
