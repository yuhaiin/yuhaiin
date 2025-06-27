package networksetup

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer/interfaces"
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

type HardwarePort struct {
	Port    string
	Device  string
	Address string
}

func ListAllHardwarePorts() ([]HardwarePort, error) {
	log.Info("list all hardware ports", "cmd", "networksetup -listallhardwareports")

	output, err := exec.Command("networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list all hardware ports: %w, output: %s", err, string(output))
	}

	var hps []HardwarePort
	for v := range strings.SplitSeq(string(output), "\n\n") {
		v := strings.TrimSpace(v)
		if v == "" {
			continue
		}

		fields := strings.Split(v, "\n")
		if len(fields) < 3 {
			continue
		}

		var hp HardwarePort
		for _, field := range fields {
			switch {
			case strings.Contains(field, "Device:"):
				hp.Device = strings.TrimSpace(strings.TrimPrefix(field, "Device: "))
			case strings.Contains(field, "Ethernet Address:"):
				hp.Address = strings.TrimSpace(strings.TrimPrefix(field, "Ethernet Address: "))
			case strings.Contains(field, "Hardware Port:"):
				hp.Port = strings.TrimSpace(strings.TrimPrefix(field, "Hardware Port: "))
			}
		}

		if hp.Port == "" || hp.Device == "" || hp.Address == "" {
			continue
		}

		hps = append(hps, hp)
	}

	return hps, nil
}

func GetHardwarePortByDevice(device string) (HardwarePort, error) {
	hps, err := ListAllHardwarePorts()
	if err != nil {
		return HardwarePort{}, err
	}

	for _, hp := range hps {
		if hp.Device == device {
			return hp, nil
		}
	}

	return HardwarePort{}, fmt.Errorf("device %s not found", device)
}

func GetDefaultHardwarePort() (HardwarePort, error) {
	dr, err := interfaces.DefaultRoute()
	if err != nil {
		return HardwarePort{}, err
	}

	return GetHardwarePortByDevice(dr.InterfaceName)
}
