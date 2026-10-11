//go:build darwin

package dataplane

import (
	"fmt"
	"os/exec"
	"strings"
)

// Client-side host networking on macOS.
//
// The shape is the Linux file's, deliberately: the same ClientNetConfig, the
// same Apply/Revert contract, the same "record what we installed and remove
// exactly that" discipline. What differs is only the commands, because macOS
// has no iproute2 — `ifconfig` addresses the interface, `route` edits the
// table, and `networksetup` owns the resolver list.
//
// # Why utun addressing looks odd
//
// A utun is a point-to-point interface, so `ifconfig utun3 inet A B` takes the
// local address AND the peer's. There is no VPN peer address to give it: the
// server's inner address is not something every protocol here reports, and the
// tunnel subnet's connected route is what actually matters. So the local
// address is given as its own peer, which is what every macOS VPN client does
// and what makes the netmask-derived route appear.
//
// # What is not here
//
// The kill switch. `route` has no blackhole equivalent that survives the
// interface going away in the way the Linux one does — the honest macOS answer
// is a packet filter (pf), which means owning firewall state on the user's
// host, and that is a much larger promise than the plan for the Linux one made.
// NewKillSwitch therefore refuses on macOS rather than half-delivering, which
// is the same choice the Linux one makes for a protocol with no single peer.

// ClientRouter applies and reverts client-side networking on macOS. It shells
// out to ifconfig, route and networksetup; it requires root.
type ClientRouter struct {
	cfg       ClientNetConfig
	gwIP      string
	gwDev     string
	installed bool
	addedHost bool
	addedDef  bool
	addedDef6 bool
	serverV6  bool
	dns       dnsBackend
	added     []addedRoute
}

// addedRoute is one prefix this router put in the host's table.
type addedRoute struct {
	prefix string
	v6     bool
}

// NewClientRouter creates a router for the given configuration.
func NewClientRouter(cfg ClientNetConfig) *ClientRouter { return &ClientRouter{cfg: cfg} }

// DNSBackend names the mechanism Apply used to install resolvers, or "".
func (r *ClientRouter) DNSBackend() string {
	if r.dns == nil {
		return ""
	}
	return r.dns.name()
}

// Apply configures the utun address, adds a host route to the server via the
// physical gateway, and (for a full tunnel) the two /1 halves.
func (r *ClientRouter) Apply() error {
	r.serverV6 = r.cfg.ServerIP != nil && r.cfg.ServerIP.To4() == nil

	gwIP, gwDev, err := defaultRoute(r.serverV6)
	if err != nil {
		return fmt.Errorf("read default route: %w", err)
	}
	r.gwIP, r.gwDev = gwIP, gwDev

	if r.cfg.AssignedIP != nil {
		mask := "255.255.255.0"
		if r.cfg.Netmask != nil {
			mask = r.cfg.Netmask.String()
		}
		// Local address as its own peer -- see the header.
		if err := run([]string{"ifconfig", r.cfg.TUNName, "inet",
			r.cfg.AssignedIP.String(), r.cfg.AssignedIP.String(), "netmask", mask, "up"}); err != nil {
			return err
		}
		r.installed = true
	}
	if r.cfg.AssignedIP6 != nil {
		prefix6 := r.cfg.Prefix6
		if prefix6 == 0 || prefix6 == 128 {
			prefix6 = 64
		}
		if err := run([]string{"ifconfig", r.cfg.TUNName, "inet6",
			fmt.Sprintf("%s/%d", r.cfg.AssignedIP6, prefix6), "up"}); err != nil {
			return err
		}
		r.installed = true
	}

	// Host route to the server through the physical gateway, so encapsulated
	// packets are not themselves routed into the tunnel.
	if r.cfg.ServerIP != nil && gwIP != "" {
		if err := run(routeCmd(r.serverV6, "add", "-host", r.cfg.ServerIP.String(), gwIP)); err != nil {
			if !alreadyExists(err) {
				return err
			}
		} else {
			r.addedHost = true
		}
	}

	if r.cfg.FullTunnel {
		if r.cfg.AssignedIP != nil {
			for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
				if err := run(routeCmd(false, "add", "-net", half, "-interface", r.cfg.TUNName)); err != nil {
					return err
				}
			}
			r.addedDef = true
		}
		if r.cfg.AssignedIP6 != nil {
			for _, half := range []string{"::/1", "8000::/1"} {
				if err := run(routeCmd(true, "add", "-net", half, "-interface", r.cfg.TUNName)); err != nil {
					return err
				}
			}
			r.addedDef6 = true
		}
	}

	for _, n := range r.cfg.Routes {
		v6 := n.IP.To4() == nil
		if err := run(routeCmd(v6, "add", "-net", n.String(), "-interface", r.cfg.TUNName)); err != nil {
			if !alreadyExists(err) {
				return fmt.Errorf("route %s: %w", n, err)
			}
			continue
		}
		r.added = append(r.added, addedRoute{prefix: n.String(), v6: v6})
	}
	for _, n := range r.cfg.Excludes {
		v6 := n.IP.To4() == nil
		exGW := gwIP
		if v6 != r.serverV6 {
			var err error
			if exGW, _, err = defaultRoute(v6); err != nil {
				return fmt.Errorf("exclude %s: no default route to send it via: %w", n, err)
			}
		}
		if err := run(routeCmd(v6, "add", "-net", n.String(), exGW)); err != nil {
			if !alreadyExists(err) {
				return fmt.Errorf("exclude %s: %w", n, err)
			}
			continue
		}
		r.added = append(r.added, addedRoute{prefix: n.String(), v6: v6})
	}

	if !r.cfg.NoDNS && len(r.cfg.DNS) > 0 {
		be := newDNSBackend()
		if err := be.apply(r.cfg.TUNName, r.cfg.DNS, r.cfg.FullTunnel); err != nil {
			return fmt.Errorf("dns (%s): %w", be.name(), err)
		}
		r.dns = be
	}
	return nil
}

// Revert removes everything Apply installed. Best-effort, like the Linux one:
// an error on one item must not stop the others coming down.
func (r *ClientRouter) Revert() error {
	var errs []string
	if r.dns != nil {
		if err := r.dns.revert(); err != nil {
			errs = append(errs, err.Error())
		}
		r.dns = nil
	}
	for i := len(r.added) - 1; i >= 0; i-- {
		a := r.added[i]
		if err := run(routeCmd(a.v6, "delete", "-net", a.prefix)); err != nil {
			errs = append(errs, err.Error())
		}
	}
	r.added = nil
	if r.addedDef {
		for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := run(routeCmd(false, "delete", "-net", half)); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if r.addedDef6 {
		for _, half := range []string{"::/1", "8000::/1"} {
			if err := run(routeCmd(true, "delete", "-net", half)); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if r.addedHost && r.cfg.ServerIP != nil {
		if err := run(routeCmd(r.serverV6, "delete", "-host", r.cfg.ServerIP.String())); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if r.installed {
		_ = run([]string{"ifconfig", r.cfg.TUNName, "down"})
	}
	if len(errs) > 0 {
		return fmt.Errorf("revert: %s", strings.Join(errs, "; "))
	}
	return nil
}

// routeCmd builds a route(8) invocation. -n keeps it from doing reverse DNS on
// every address it prints, which on a half-configured tunnel is a stall rather
// than a nicety.
func routeCmd(v6 bool, args ...string) []string {
	cmd := []string{"route", "-n"}
	if v6 {
		cmd = append(cmd, "-inet6")
	}
	return append(cmd, args...)
}

// alreadyExists reports whether route(8) refused because the entry is there.
// macOS says "File exists" like Linux does, which is the one string both
// platforms happen to share here.
func alreadyExists(err error) bool {
	return strings.Contains(err.Error(), "File exists") ||
		strings.Contains(err.Error(), "already in table")
}

// defaultRoute returns the current default gateway and device for a family, by
// parsing `route -n get default`. The output is a block of "key: value" lines;
// the two that matter are "gateway" and "interface".
func defaultRoute(v6 bool) (gwIP, dev string, err error) {
	args := []string{"-n", "get"}
	if v6 {
		args = append(args, "-inet6")
	}
	args = append(args, "default")
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "gateway":
			gwIP = strings.TrimSpace(v)
		case "interface":
			dev = strings.TrimSpace(v)
		}
	}
	if gwIP == "" || dev == "" {
		return "", "", fmt.Errorf("no default route found")
	}
	return gwIP, dev, nil
}

func run(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
