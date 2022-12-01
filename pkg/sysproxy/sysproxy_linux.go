//go:build !android
// +build !android

package sysproxy

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

func SetSysProxy(http, socks5 string) {
	var httpHostname, httpPort string
	var socks5Hostname, socks5Port string

	if http == "" && socks5 == "" {
		return
	}

	if http != "" {
		httpHostname, httpPort, _ = net.SplitHostPort(http)
		log.Debugf("set http system hostname: %s, port: %s\n", httpHostname, httpPort)
	}
	if socks5 != "" {
		socks5Hostname, socks5Port, _ = net.SplitHostPort(socks5)
		log.Debugf("set socks5 system hostname: %s, port: %s\n", socks5Hostname, socks5Port)
	}

	gnomeSetSysProxy(httpHostname, httpPort, socks5Hostname, socks5Port)
	kdeSetSysProxy(httpHostname, httpPort, socks5Hostname, socks5Port)
}

func gnomeSetSysProxy(httpH, httpP, socks5H, socks5P string) {
	// GNOME
	gsettings, err := exec.LookPath("gsettings")
	if err != nil {
		log.Errorln(err)
		return
	}
	//https://wiki.archlinux.org/index.php/Proxy_server
	//gsettings set org.gnome.system.proxy mode 'manual'
	//gsettings set org.gnome.system.proxy.http host 'proxy.localdomain.com'
	//gsettings set org.gnome.system.proxy.http port 8080
	//gsettings set org.gnome.system.proxy.ftp host 'proxy.localdomain.com'
	//gsettings set org.gnome.system.proxy.ftp port 8080
	//gsettings set org.gnome.system.proxy.https host 'proxy.localdomain.com'
	//gsettings set org.gnome.system.proxy.https port 8080
	//gsettings set org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12' , '*.localdomain.com' ]"
	//  gsettings set org.gnome.system.proxy mode 'manual'
	_ = exec.Command(gsettings, "set", "org.gnome.system.proxy", "mode", "manual").Run()
	if httpH != "" || httpP != "" {
		_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.http", "host", httpH).Run()
		_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.http", "port", httpP).Run()
		_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.https", "host", httpH).Run()
		_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.https", "port", httpP).Run()
	}
	if socks5H != "" || socks5P != "" {
		_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.socks", "host", socks5H).Run()
		_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.socks", "port", socks5P).Run()
	}
	_ = exec.Command(gsettings, "set", "org.gnome.system.proxy", "ignore-hosts", "['localhost','::1','0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/29','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/3']").Run()
}

func kdeSetSysProxy(httpH, httpP, socks5H, socks5P string) {

	// KDE
	// if os.Getenv("XDG_SESSION_DESKTOP") != "KDE" {
	// return
	// }

	kwriteconfig5, err := exec.LookPath("kwriteconfig5")
	if err != nil {
		log.Errorln(err)
		return
	}

	// kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key httpProxy "http://127.0.0.1 8188"
	_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "NoProxyFor", "0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/29,192.0.2.0/24,192.88.99.0/24,192.168.0.0/16,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/3").Run()
	_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1").Run()
	if httpH != "" || httpP != "" {
		_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", fmt.Sprintf("http://%s %s", httpH, httpP)).Run()
		_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", fmt.Sprintf("http://%s %s", httpH, httpP)).Run()
	}
	//_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ftpProxy", fmt.Sprintf("http://%s %s", httpUrl.Hostname(), httpUrl.Port())).Run()
	if socks5H != "" || socks5P != "" {
		_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", fmt.Sprintf("socks://%s %s", socks5H, socks5P)).Run()
	}
	// Notify kioslaves to reload system proxy configuration.
	dbusSend, err := exec.LookPath("dbus-send")
	if err != nil {
		log.Errorln(err)
		return
	}
	_ = exec.Command(dbusSend, "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''")
}

func UnsetSysProxy() {
	gnomeUnsetSysProxy()
	kdeUnsetSysProxy()
}

func gnomeUnsetSysProxy() {
	gsettings, err := exec.LookPath("gsettings")
	if err != nil {
		log.Errorln(err)
		return
	}

	// GNOME
	//  gsettings set org.gnome.system.proxy mode 'manual'
	_ = exec.Command(gsettings, "set", "org.gnome.system.proxy", "mode", "none").Run()
	_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.http", "host", "0").Run()
	_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.http", "port", "0").Run()
	_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.https", "host", "0").Run()
	_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.https", "port", "0").Run()
	_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.socks", "host", "0").Run()
	_ = exec.Command(gsettings, "set", "org.gnome.system.proxy.socks", "port", "0").Run()
}

func kdeUnsetSysProxy() {
	// if os.Getenv("XDG_SESSION_DESKTOP") != "KDE" {
	// return
	// }
	kwriteconfig5, err := exec.LookPath("kwriteconfig5")
	if err != nil {
		log.Errorln(err)
		return
	}

	// KDE
	// kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key httpProxy "http://127.0.0.1 8188"
	_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0").Run()
	_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", "").Run()
	_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", "").Run()
	//_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ftpProxy", "").Run()
	_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "socksProxy", "").Run()
	// Notify kioslaves to reload system proxy configuration.
	dbusSend, err := exec.LookPath("dbus-send")
	if err != nil {
		log.Errorln(err)
		return
	}
	_ = exec.Command(dbusSend, "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''")
}
