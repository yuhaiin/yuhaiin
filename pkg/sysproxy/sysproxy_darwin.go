package sysproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

func SetSysProxy(httpHostname, httpPort, socks5Hostname, socks5Port string) {
	if httpHostname == "" && socks5Hostname == "" {
		return
	}

	if httpHostname != "" {
		log.Debug("set http system proxy", "hostname", httpHostname, "port", httpPort)
	}
	if socks5Hostname != "" {
		log.Debug("set socks5 system proxy", "hostname", socks5Hostname, "port", socks5Port)
	}

	networksetup := "/usr/sbin/networksetup"

	services, err := getServices(networksetup)
	if err != nil {
		log.Error("set sysproxy failed", "err", err)
		return
	}

	for _, service := range services {
		if httpHostname != "" {
			_ = exec.Command(networksetup, "-setwebproxystate", service, "on").Run()
			_ = exec.Command(networksetup, "-setsecurewebproxystate", service, "on").Run()
			_ = exec.Command(networksetup, "-setwebproxy", service, httpHostname, httpPort).Run()
			_ = exec.Command(networksetup, "-setsecurewebproxy", service, httpHostname, httpPort).Run()
		}

		if socks5Hostname != "" {
			_ = exec.Command(networksetup, "-setsocksfirewallproxystate", service, "on").Run()
			_ = exec.Command(networksetup, "-setsocksfirewallproxy", service, socks5Hostname, socks5Port).Run()
		}

		_ = exec.Command(networksetup, append([]string{"-setproxybypassdomains", service}, priAddr...)...).Run()
	}

}

func UnsetSysProxy() {
	networksetup := "/usr/sbin/networksetup"

	services, err := getServices(networksetup)
	if err != nil {
		log.Error("set sysproxy failed", "err", err)
		return
	}

	for _, service := range services {
		// _ = exec.Command(networksetup, "-setproxyautodiscovery", service, "off").Run()
		_ = exec.Command(networksetup, "-setwebproxystate", service, "off").Run()
		_ = exec.Command(networksetup, "-setsecurewebproxystate", service, "off").Run()
		_ = exec.Command(networksetup, "-setsocksfirewallproxystate", service, "off").Run()
		_ = exec.Command(networksetup, "-setproxybypassdomains", service, "").Run()
	}
}

func getServices(networksetup string) ([]string, error) {
	output, err := exec.Command(networksetup, "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}

	r := bufio.NewScanner(bytes.NewReader(output))

	resp := make([]string, 0)

	for r.Scan() {
		if !strings.Contains(r.Text(), "*") {
			resp = append(resp, r.Text())
		}
	}

	if len(resp) == 0 {
		return nil, fmt.Errorf("all services is disabled")
	}

	return resp, nil
}
