package sysproxy

import (
	"net"
	"net/url"
	"os"
	"os/exec"
	"testing"
)

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
	t.Log(net.SplitHostPort(":9090"))
	t.Log(net.SplitHostPort("[]:111"))
	t.Log(net.SplitHostPort("[ff::ff]:111"))
}
