//go:build darwin

package dataplane

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// DNS on macOS: networksetup, against the primary network service.
//
// macOS has no /etc/resolv.conf an application can usefully edit -- the file is
// generated from the SystemConfiguration store and rewriting it changes nothing
// that mDNSResponder consults, which is the same trap systemd-resolved sets on
// Linux. The supported route is `networksetup -setdnsservers <service> …`, and
// the awkward part is that it names a *service* ("Wi-Fi", "USB 10/100/1000 LAN")
// rather than an interface, so the interface the default route points at has to
// be mapped back to one.
//
// # Why not the utun link
//
// There is no per-link resolver setting to put on a utun the way resolvectl
// puts one on a Linux link: SystemConfiguration keys DNS by service, and a utun
// veepin created has no service entry. So the tunnel's resolvers replace the
// primary service's for the tunnel's lifetime and the originals are put back on
// teardown -- which is the resolv.conf backend's shape, not the resolvectl one.
//
// The split-tunnel consequence follows and is the same as on Linux without
// resolved: there is nowhere to say "these names via the tunnel, those via the
// old resolver", so a split tunnel keeps the host's resolvers after the
// tunnel's rather than replacing them.

// networksetupDNS drives macOS's SystemConfiguration DNS through networksetup.
type networksetupDNS struct {
	service  string   // the primary network service, e.g. "Wi-Fi"
	original []string // its resolvers before we touched them
	applied  bool
	run      execRunner
	output   func(args []string) ([]byte, error)
}

// newDNSBackend picks the only mechanism that takes effect on macOS.
func newDNSBackend() dnsBackend {
	return &networksetupDNS{run: run, output: commandOutput}
}

func (d *networksetupDNS) name() string { return "networksetup" }

func (d *networksetupDNS) apply(_ string, servers []net.IP, fullTunnel bool) error {
	svc, err := primaryNetworkService(d.output)
	if err != nil {
		return err
	}
	d.service = svc

	current, err := currentDNSServers(d.output, svc)
	if err != nil {
		return err
	}
	d.original = current

	args := []string{"networksetup", "-setdnsservers", svc}
	for _, s := range servers {
		args = append(args, s.String())
	}
	if !fullTunnel {
		// The host's resolvers follow the tunnel's, because there is nowhere on
		// this platform to say which names go where -- and the names outside a
		// split tunnel still have to resolve. A full tunnel keeps only ours,
		// because keeping any other is the leak.
		args = append(args, current...)
	}
	if err := d.run(args); err != nil {
		return err
	}
	d.applied = true
	return nil
}

func (d *networksetupDNS) revert() error {
	if !d.applied {
		return nil
	}
	d.applied = false
	args := []string{"networksetup", "-setdnsservers", d.service}
	if len(d.original) == 0 {
		// "Empty" is networksetup's own word for "no manual servers, go back to
		// DHCP". Passing nothing at all is a usage error, not a clear.
		args = append(args, "Empty")
	} else {
		args = append(args, d.original...)
	}
	return d.run(args)
}

// primaryNetworkService maps the interface the default route points at to the
// service name networksetup wants.
//
// `networksetup -listnetworkserviceorder` prints, per service, a name line and
// a "(Hardware Port: …, Device: enN)" line, so the device is the join key. The
// order it prints is the service order, which is why the FIRST match for the
// default route's device is the right answer rather than any match.
func primaryNetworkService(output func([]string) ([]byte, error)) (string, error) {
	_, dev, err := defaultRoute(false)
	if err != nil {
		return "", fmt.Errorf("networksetup: find the primary interface: %w", err)
	}
	out, err := output([]string{"networksetup", "-listnetworkserviceorder"})
	if err != nil {
		return "", fmt.Errorf("networksetup: list services: %w", err)
	}

	// "(1) Wi-Fi" then "(Hardware Port: Wi-Fi, Device: en0)".
	var name string
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "("); ok {
			if _, rest, found := strings.Cut(after, ") "); found {
				name = rest
				continue
			}
		}
		if strings.Contains(line, "Device: "+dev+")") && name != "" {
			return name, nil
		}
	}
	return "", fmt.Errorf("networksetup: no network service uses %s, so there is nowhere to "+
		"set the tunnel's resolvers; pass -no-dns to leave DNS alone", dev)
}

// currentDNSServers reads a service's manual resolvers. networksetup answers
// with a sentence rather than an empty list when there are none, which is why
// the check is on the prose and not on the line count.
func currentDNSServers(output func([]string) ([]byte, error), service string) ([]string, error) {
	out, err := output([]string{"networksetup", "-getdnsservers", service})
	if err != nil {
		return nil, fmt.Errorf("networksetup: read %s's resolvers: %w", service, err)
	}
	text := strings.TrimSpace(string(out))
	if strings.Contains(text, "aren't any DNS Servers set") {
		return nil, nil
	}
	var servers []string
	for line := range strings.SplitSeq(text, "\n") {
		if ip := net.ParseIP(strings.TrimSpace(line)); ip != nil {
			servers = append(servers, ip.String())
		}
	}
	return servers, nil
}

// commandOutput runs a command for its stdout, which the two networksetup
// queries above need and run() (which only reports failure) does not give.
func commandOutput(args []string) ([]byte, error) {
	out, err := exec.Command(args[0], args[1:]...).Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}
