// +build !windows

package process

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
)

func SetSysProxy() {
	httpUrl, _ := url.Parse("//" + conFig.HttpProxyAddress)
	socks5Url, _ := url.Parse("//" + conFig.Socks5ProxyAddress)
	// GNOME
	//  gsettings set org.gnome.system.proxy mode 'manual'
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "manual").Run()
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "host", httpUrl.Hostname()).Run()
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "port", httpUrl.Port()).Run()
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "host", httpUrl.Hostname()).Run()
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "port", httpUrl.Port()).Run()
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy.socks", "host", socks5Url.Hostname()).Run()
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy.socks", "port", socks5Url.Port()).Run()
	if os.Getenv("XDG_SESSION_DESKTOP") != "KDE" {
		return
	}
	// KDE
	// kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key httpProxy "http://127.0.0.1 8188"
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "NoProxyFor", "0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/29,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/3").Run()
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1").Run()
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", fmt.Sprintf("http://%s %s", httpUrl.Hostname(), httpUrl.Port())).Run()
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", fmt.Sprintf("http://%s %s", httpUrl.Hostname(), httpUrl.Port())).Run()
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ftpProxy", fmt.Sprintf("http://%s %s", httpUrl.Hostname(), httpUrl.Port())).Run()
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", fmt.Sprintf("socks://%s %s", socks5Url.Hostname(), socks5Url.Port())).Run()
}

func UnsetSysProxy() {
	// GNOME
	//  gsettings set org.gnome.system.proxy mode 'manual'
	_ = exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "none").Run()
	if os.Getenv("XDG_SESSION_DESKTOP") != "KDE" {
		return
	}
	// KDE
	// kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key httpProxy "http://127.0.0.1 8188"
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0").Run()
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", "").Run()
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", "").Run()
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ftpProxy", "").Run()
	_ = exec.Command("kwriteconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", "").Run()
}
