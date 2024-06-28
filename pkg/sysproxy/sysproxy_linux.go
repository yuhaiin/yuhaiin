//go:build !android
// +build !android

package sysproxy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

func SetSysProxy(httpHostname, httpPort, socks5Hostname, socks5Port string) {
	if httpHostname != "" {
		log.Debug("set http system proxy", "hostname", httpHostname, "port", httpPort)
	}
	if socks5Hostname != "" {
		log.Debug("set socks5 system proxy", "hostname", socks5Hostname, "port", socks5Port)
	}

	if err := gnomeSetSysProxy(httpHostname, httpPort, socks5Hostname, socks5Port); err != nil {
		log.Error("set gnome proxy failed", "err", err)
	}
	if err := kdeSetSysProxy(httpHostname, httpPort, socks5Hostname, socks5Port); err != nil {
		log.Error("set kde proxy failed", "err", err)
	}
}

func gnomeSetSysProxy(httpH, httpP, socks5H, socks5P string) error {
	// GNOME
	gsettings, err := exec.LookPath("gsettings")
	if err != nil {
		return nil
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
	_ = exec.Command(gsettings, "set", "org.gnome.system.proxy", "ignore-hosts",
		fmt.Sprintf("['%s']", strings.Join(priAddr, "','"))).Run()

	return nil
}

func getKwriteconfig5() (string, error) {
	var kwriteconfig5 string
	var err error
	for _, v := range []string{
		"kwriteconfig6",
		"kwriteconfig5",
	} {
		var er error
		kwriteconfig5, er = exec.LookPath(v)
		if er != nil {
			err = errors.Join(err, er)
			continue
		}

		break
	}

	if kwriteconfig5 == "" {
		return "", err
	}

	return kwriteconfig5, nil
}

func kdeSetSysProxy(httpH, httpP, socks5H, socks5P string) error {
	// KDE
	if os.Getenv("XDG_SESSION_DESKTOP") != "KDE" {
		return nil
	}

	kwriteconfig5, err := getKwriteconfig5()
	if err != nil {
		return nil
	}

	// kwriteconfig5 --file kioslaverc --group 'Proxy Settings' --key httpProxy "http://127.0.0.1 8188"
	_ = exec.Command(kwriteconfig5, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "NoProxyFor", strings.Join(priAddr, ",")).Run()
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
		return fmt.Errorf("lookup dbus-send failed: %w", err)
	}
	_ = exec.Command(dbusSend, "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''")

	return nil
}

func UnsetSysProxy() {
	if err := gnomeUnsetSysProxy(); err != nil {
		log.Error("unset gnome proxy failed", "err", err)
	}
	if err := kdeUnsetSysProxy(); err != nil {
		log.Error("unset kde proxy failed", "err", err)
	}
}

func gnomeUnsetSysProxy() error {
	gsettings, err := exec.LookPath("gsettings")
	if err != nil {
		return nil
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

	return nil
}

func kdeUnsetSysProxy() error {
	if os.Getenv("XDG_SESSION_DESKTOP") != "KDE" {
		return nil
	}

	kwriteconfig5, err := getKwriteconfig5()
	if err != nil {
		return nil
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
		return fmt.Errorf("lookup dbus-send failed: %w", err)
	}
	_ = exec.Command(dbusSend, "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:''")

	return nil
}
