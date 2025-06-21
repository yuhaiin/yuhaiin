package networksetup

import (
	"net"
	"os/exec"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

// ListAllNetworkServices list all network services
func ListAllNetworkServices() ([]string, error) {
	log.Info("list all network services", "cmd", "networksetup -listallnetworkservices")

	output, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}

	fields := strings.Split(string(output), "\n")
	if len(fields) > 0 {
		fields = fields[1:]
	}

	resp := make([]string, 0, len(fields))
	for _, v := range fields {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		resp = append(resp, v)
	}

	return resp, nil
}

// ListAllDNSServers list all dns servers
func ListAllDNSServers(service string) ([]string, error) {
	log.Info("list all dns servers", "cmd", "networksetup -getdnsservers "+service)

	output, err := exec.Command("networksetup", "-getdnsservers", service).Output()
	if err != nil {
		return nil, err
	}

	fields := strings.Split(string(output), "\n")

	resp := make([]string, 0, len(fields))
	for _, v := range fields {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}

		if ip := net.ParseIP(v); ip == nil {
			continue
		}

		resp = append(resp, v)
	}

	return resp, nil
}

// SetDNSServers set dns servers, if servers is nil, set empty
func SetDNSServers(service string, servers []string) error {
	cmd := exec.Command("networksetup", "-setdnsservers", service)

	if servers == nil {
		cmd.Args = append(cmd.Args, "empty")
	} else {
		cmd.Args = append(cmd.Args, servers...)
	}

	log.Info("set dns servers", "cmd", cmd.String())

	return cmd.Run()
}
