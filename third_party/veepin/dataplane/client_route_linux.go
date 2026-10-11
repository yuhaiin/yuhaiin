package dataplane

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// ClientRouter applies and reverts client-side networking. It shells out to the
// Linux iproute2 tools; it requires CAP_NET_ADMIN. Reverting restores the prior
// default route.
type ClientRouter struct {
	cfg       ClientNetConfig
	prevGWIP  string // previous default gateway, for restoration
	prevGWDev string
	installed bool
	addedHost bool
	addedDef  bool
	addedDef6 bool
	serverV6  bool       // the server's outer address is IPv6 (host route uses `ip -6`)
	dns       dnsBackend // nil until Apply installs resolvers; see client_dns.go
	// added are the -route and -exclude prefixes this router installed, in the
	// order it installed them, so Revert removes exactly those and no more. A
	// prefix that failed to install is not in here, which is what stops Revert
	// from deleting a route the host already had.
	added []addedRoute
}

// addedRoute is one prefix this router put in the host's table.
type addedRoute struct {
	prefix string
	viaGW  bool // installed via the physical gateway (an exclude) rather than the TUN
	v6     bool
}

// NewClientRouter creates a router for the given configuration.
func NewClientRouter(cfg ClientNetConfig) *ClientRouter {
	return &ClientRouter{cfg: cfg}
}

// DNSBackend names the mechanism Apply used to install resolvers, or "" if it
// installed none. Callers log it: which of the two mechanisms edited the host
// is the first thing anyone asks when name resolution goes wrong.
func (r *ClientRouter) DNSBackend() string {
	if r.dns == nil {
		return ""
	}
	return r.dns.name()
}

// Apply configures the TUN address, brings the interface up, adds a host route
// to the VPN server via the existing default gateway, and (for a full tunnel)
// replaces the default route to send everything through the TUN.
func (r *ClientRouter) Apply() error {
	// The server host route (and the default it is pinned through) must be in the
	// same family as the server's OUTER address — an IPv6 underlay is reached via
	// the IPv6 default gateway, not the IPv4 one.
	r.serverV6 = r.cfg.ServerIP != nil && r.cfg.ServerIP.To4() == nil

	// Record the current default route so we can (a) pin a host route to the
	// server through it and (b) restore it on teardown.
	gwIP, gwDev, err := defaultRoute(r.serverV6)
	if err != nil {
		return fmt.Errorf("read default route: %w", err)
	}
	r.prevGWIP, r.prevGWDev = gwIP, gwDev

	var steps [][]string
	if r.cfg.AssignedIP != nil {
		prefix := maskToPrefix(r.cfg.Netmask)
		steps = append(steps, []string{"ip", "addr", "add", fmt.Sprintf("%s/%d", r.cfg.AssignedIP, prefix), "dev", r.cfg.TUNName})
	}
	if r.cfg.AssignedIP6 != nil {
		// Widen a host assignment (/128) or an unset prefix to the conventional
		// /64, so the tunnel's connected route reaches the peer and gateway in a
		// split tunnel — the IPv6 counterpart of defaulting a missing IPv4 netmask
		// to /24. A full tunnel routes ::/0 regardless.
		prefix6 := r.cfg.Prefix6
		if prefix6 == 0 || prefix6 == 128 {
			prefix6 = 64
		}
		steps = append(steps, []string{"ip", "-6", "addr", "add", fmt.Sprintf("%s/%d", r.cfg.AssignedIP6, prefix6), "dev", r.cfg.TUNName})
	}
	steps = append(steps, []string{"ip", "link", "set", r.cfg.TUNName, "up"})
	for _, s := range steps {
		if err := run(s); err != nil {
			return err
		}
	}
	r.installed = true

	// Host route: reach the VPN server via the physical gateway, so that the
	// encapsulated ESP packets are NOT themselves routed into the tunnel. The
	// route family follows the server's outer address.
	if r.cfg.ServerIP != nil && gwIP != "" {
		add := append(ipCmd(r.serverV6), "route", "add", r.cfg.ServerIP.String(), "via", gwIP, "dev", gwDev)
		if err := run(add); err != nil {
			// Non-fatal if it already exists.
			if !strings.Contains(err.Error(), "File exists") {
				return err
			}
		} else {
			r.addedHost = true
		}
	}

	// Full tunnel: split the default route into two /1 routes via the TUN,
	// which override the existing default without deleting it (a common VPN
	// technique that makes restoration trivial).
	if r.cfg.FullTunnel {
		if r.cfg.AssignedIP != nil {
			for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
				if err := run([]string{"ip", "route", "add", half, "dev", r.cfg.TUNName}); err != nil {
					return err
				}
			}
			r.addedDef = true
		}
		if r.cfg.AssignedIP6 != nil {
			for _, half := range []string{"::/1", "8000::/1"} {
				if err := run([]string{"ip", "-6", "route", "add", half, "dev", r.cfg.TUNName}); err != nil {
					return err
				}
			}
			r.addedDef6 = true
		}
	}

	// Split-tunnel routes, before DNS so that a resolver reached through one of
	// them is routable by the time the resolver is installed.
	for _, n := range r.cfg.Routes {
		v6 := n.IP.To4() == nil
		cmd := append(ipCmd(v6), "route", "add", n.String(), "dev", r.cfg.TUNName)
		if err := run(cmd); err != nil {
			if !strings.Contains(err.Error(), "File exists") {
				return fmt.Errorf("route %s: %w", n, err)
			}
			continue // already present and not ours; leave it alone on the way out
		}
		r.added = append(r.added, addedRoute{prefix: n.String(), v6: v6})
	}
	// Excludes go via the physical gateway, which is the same mechanism as the
	// server host route: a more specific prefix beats the tunnel's. They need a
	// gateway to point at, and a host with no default route in that family has
	// none -- said plainly rather than installed as something that will not work.
	for _, n := range r.cfg.Excludes {
		v6 := n.IP.To4() == nil
		exGW, exDev := gwIP, gwDev
		if v6 != r.serverV6 {
			// The recorded gateway is the server's family. An exclude in the
			// other family needs that family's default route.
			var err error
			if exGW, exDev, err = defaultRoute(v6); err != nil {
				return fmt.Errorf("exclude %s: no default route to send it via: %w", n, err)
			}
		}
		cmd := append(ipCmd(v6), "route", "add", n.String(), "via", exGW, "dev", exDev)
		if err := run(cmd); err != nil {
			if !strings.Contains(err.Error(), "File exists") {
				return fmt.Errorf("exclude %s: %w", n, err)
			}
			continue
		}
		r.added = append(r.added, addedRoute{prefix: n.String(), viaGW: true, v6: v6})
	}

	// DNS last, because it is the only step that edits state outside this
	// machine's routing table and the only one whose failure is worth
	// distinguishing: everything above it has already succeeded by the time we
	// get here, and Revert undoes whatever did.
	if !r.cfg.NoDNS && len(r.cfg.DNS) > 0 {
		be := newDNSBackend()
		if err := be.apply(r.cfg.TUNName, r.cfg.DNS, r.cfg.FullTunnel); err != nil {
			return fmt.Errorf("dns (%s): %w", be.name(), err)
		}
		r.dns = be
	}
	return nil
}

// Revert removes the routes and address this router added. Best-effort: errors
// are collected but do not stop cleanup.
func (r *ClientRouter) Revert() error {
	var errs []string
	// DNS first, in reverse order of application: the resolvectl backend names
	// the link, and the link is about to go down.
	if r.dns != nil {
		if err := r.dns.revert(); err != nil {
			errs = append(errs, err.Error())
		}
		r.dns = nil
	}
	// Reverse order, so a route that depended on another coming first is
	// removed before the one it depended on.
	for i := len(r.added) - 1; i >= 0; i-- {
		a := r.added[i]
		del := append(ipCmd(a.v6), "route", "del", a.prefix)
		if err := run(del); err != nil {
			errs = append(errs, err.Error())
		}
	}
	r.added = nil
	if r.addedDef {
		for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := run([]string{"ip", "route", "del", half, "dev", r.cfg.TUNName}); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if r.addedDef6 {
		for _, half := range []string{"::/1", "8000::/1"} {
			if err := run([]string{"ip", "-6", "route", "del", half, "dev", r.cfg.TUNName}); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if r.addedHost && r.cfg.ServerIP != nil {
		del := append(ipCmd(r.serverV6), "route", "del", r.cfg.ServerIP.String())
		if err := run(del); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if r.installed {
		// Bringing the link down and removing the address; the kernel drops the
		// connected route automatically.
		_ = run([]string{"ip", "link", "set", r.cfg.TUNName, "down"})
	}
	if len(errs) > 0 {
		return fmt.Errorf("revert: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ipCmd is the iproute2 command prefix for the given family: `ip` for IPv4,
// `ip -6` for IPv6. Callers append the route/addr subcommand and arguments.
func ipCmd(v6 bool) []string {
	if v6 {
		return []string{"ip", "-6"}
	}
	return []string{"ip"}
}

// defaultRoute returns the current default gateway IP and device for the given
// family (IPv4 by default, IPv6 when v6 is set).
func defaultRoute(v6 bool) (gwIP, dev string, err error) {
	fam := "-4"
	if v6 {
		fam = "-6"
	}
	out, err := exec.Command("ip", fam, "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	// Example: "default via 192.168.1.1 dev eth0 proto dhcp ..."
	fields := strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "via":
			gwIP = fields[i+1]
		case "dev":
			dev = fields[i+1]
		}
	}
	if gwIP == "" || dev == "" {
		return "", "", fmt.Errorf("no default route found")
	}
	return gwIP, dev, nil
}

func maskToPrefix(mask net.IP) int {
	if mask == nil {
		return 24
	}
	m := net.IPMask(mask.To4())
	ones, _ := m.Size()
	if ones == 0 {
		return 24
	}
	return ones
}

func run(args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
