package dataplane

import (
	"fmt"
	"net"
	"strings"
)

// The kill switch: what happens to the host's traffic when the tunnel dies
// without being asked to.
//
// ClientRouter.Revert restores the pre-VPN default route, which is right for a
// Ctrl-C and wrong for a tunnel that died on its own: the user asked for their
// traffic to go through the VPN, and it silently stopped doing so. Worse, the
// reconnection loop makes the window real rather than theoretical -- a laptop
// that loses its tunnel now spends the whole backoff sending in plaintext.
//
// # How it holds
//
// The routes ClientRouter installs for a full tunnel are the two halves
// 0.0.0.0/1 and 128.0.0.0/1, pointed at the TUN, which override the default
// without deleting it. This installs the *same two halves* as blackholes, at a
// worse metric:
//
//	0.0.0.0/1   dev tun0                  metric 0     ← while the tunnel is up
//	0.0.0.0/1   blackhole                 metric 100   ← the instant it is not
//	0.0.0.0/0   via 192.168.1.1 dev eth0               ← never reached again
//
// So it is engaged while the tunnel is *healthy* and simply waits. The kernel
// drops a device route when its device goes away, which uncovers the blackhole
// with no window at all -- whereas installing the blackhole in response to the
// teardown leaves however long that takes as plaintext.
//
// # The carve-out that makes reconnection possible
//
// A /1 blackhole covers the VPN server too, so with nothing else the re-dial
// could not reach it and the kill switch would be a brick rather than a switch.
// It therefore holds its own host route to the server, via the physical
// gateway, for as long as it is engaged -- at the same worse metric, so it is a
// distinct route from the one ClientRouter installs and is added and removed
// independently of it.
//
// This is why a protocol whose Result carries no Gateway cannot have one. A
// mesh reaches peers at many underlay addresses and there is no single one to
// carve out; engaging here would produce a host that can never reconnect. The
// caller is expected to refuse that combination rather than deliver it.
//
// # The alternative not taken
//
// Firewall rules (nftables/iptables) scoping egress to the tunnel interface are
// what a mature client does and are strictly better -- they also cover a
// process that binds a source address explicitly, which a route cannot. They
// also mean owning firewall state on the user's host, which is a far larger
// promise than owning two /1 routes. A blackhole route is the honest version of
// what this tree already does.

// killSwitchMetric is the priority the blackhole routes carry. Any value worse
// than the tunnel's own (which iproute2 installs at 0) works; 100 is far enough
// from 0 to be obviously deliberate in `ip route show`.
const killSwitchMetric = "100"

// KillSwitchConfig describes the hole to leave in an otherwise closed host.
type KillSwitchConfig struct {
	// ServerIP is the VPN server's OUTER address -- client.Result.Gateway. It
	// is the one destination that stays reachable while engaged, so that a
	// re-dial can happen. Nil is a programming error here: see the package
	// comment on why the caller must refuse that case instead.
	ServerIP net.IP
	// V4 and V6 say which families the tunnel carries. They are recorded for
	// the log line and NOT used to decide what to close.
	//
	// Closing only the families the tunnel carries was the first design, and it
	// was wrong in the one way that matters here: a v4-only tunnel on a
	// dual-stack host leaves every IPv6 packet going out the physical link, in
	// plaintext, while the operator has explicitly asked to fail closed. "A
	// family the tunnel never routed is left alone" reads like restraint and is
	// actually the leak -- a family the tunnel does not carry is exactly a
	// family that escapes it.
	//
	// So Engage closes both, always. Link-local and any other connected route
	// is more specific than a /1 and is unaffected; what stops is traffic that
	// would otherwise have left by the physical default, which is the whole
	// point of the flag.
	V4, V6 bool
}

// KillSwitch holds the blackhole routes. It is created once per `connect` and
// outlives every session, because holding across the gap is the whole point.
type KillSwitch struct {
	cfg     KillSwitchConfig
	engaged bool
	// started is set as soon as Engage begins installing anything, and is what
	// Disengage checks. It is distinct from engaged because Engage calls
	// Disengage itself to undo a partial install, at a point where engaged is
	// still false -- and distinct from "never touched", because Disengage is
	// reached from a defer that also runs on paths where Engage was refused.
	//
	// Without it, a Disengage on a switch that never engaged runs `ip route del`
	// for four prefixes it did not install, which on an unprivileged process is
	// four errors and on a privileged one is four routes belonging to somebody
	// else.
	started   bool
	addedHost bool
	gwIP      string
	gwDev     string
}

// NewKillSwitch creates a disengaged kill switch.
func NewKillSwitch(cfg KillSwitchConfig) *KillSwitch { return &KillSwitch{cfg: cfg} }

// Engaged reports whether the blackhole routes are currently installed.
func (k *KillSwitch) Engaged() bool { return k.engaged }

// Engage installs the blackhole routes and the carve-out to the server. It is
// idempotent: calling it on each successful dial is the intended use, since the
// switch is armed while the tunnel is healthy.
func (k *KillSwitch) Engage() error {
	if k.engaged {
		return nil
	}
	if k.cfg.ServerIP == nil {
		return fmt.Errorf("kill switch: no server address to keep reachable; " +
			"a protocol with no single peer cannot be fenced this way")
	}
	k.started = true
	serverV6 := k.cfg.ServerIP.To4() == nil

	// The carve-out first. Ordering matters on a live host: if the blackholes
	// went in first and the host route failed, the machine would be closed with
	// no way to reconnect, which is the failure this whole type exists to make
	// impossible.
	gwIP, gwDev, err := defaultRoute(serverV6)
	if err != nil {
		return fmt.Errorf("kill switch: read default route: %w", err)
	}
	k.gwIP, k.gwDev = gwIP, gwDev
	add := append(ipCmd(serverV6), "route", "add", k.cfg.ServerIP.String(),
		"via", gwIP, "dev", gwDev, "metric", killSwitchMetric)
	if err := run(add); err != nil {
		// Already present is fine -- it is ours from a previous engage that
		// only half came down -- but we then own deleting it.
		if !strings.Contains(err.Error(), "File exists") {
			return fmt.Errorf("kill switch: pin the server route: %w", err)
		}
	}
	k.addedHost = true

	for _, h := range k.halves() {
		if err := run(h.add()); err != nil && !strings.Contains(err.Error(), "File exists") {
			// Undo the carve-out rather than leaving a half-closed host whose
			// state no operator could guess from `ip route`.
			_ = k.Disengage()
			return fmt.Errorf("kill switch: blackhole %s: %w", h.prefix, err)
		}
	}
	k.engaged = true
	return nil
}

// Disengage removes everything Engage installed. Best-effort, like Revert: an
// error on one route must not stop the others coming down, because a partly
// closed host is worse than either state.
func (k *KillSwitch) Disengage() error {
	if !k.started {
		return nil
	}
	var errs []string
	for _, h := range k.halves() {
		if err := run(h.del()); err != nil && !strings.Contains(err.Error(), "No such process") {
			errs = append(errs, err.Error())
		}
	}
	if k.addedHost && k.cfg.ServerIP != nil {
		del := append(ipCmd(k.cfg.ServerIP.To4() == nil), "route", "del",
			k.cfg.ServerIP.String(), "metric", killSwitchMetric)
		if err := run(del); err != nil && !strings.Contains(err.Error(), "No such process") {
			errs = append(errs, err.Error())
		}
		k.addedHost = false
	}
	k.engaged, k.started = false, false
	if len(errs) > 0 {
		return fmt.Errorf("kill switch: disengage: %s", strings.Join(errs, "; "))
	}
	return nil
}

// blackholeHalf is one of the four prefixes that together cover a family.
type blackholeHalf struct {
	prefix string
	v6     bool
}

func (h blackholeHalf) cmd(verb string) []string {
	return append(ipCmd(h.v6), "route", verb, "blackhole", h.prefix, "metric", killSwitchMetric)
}

func (h blackholeHalf) add() []string { return h.cmd("add") }
func (h blackholeHalf) del() []string { return h.cmd("del") }

// halves is the set of prefixes this switch closes: two /1s per family, both
// families, always.
//
// Two /1s rather than one /0 mirrors ClientRouter exactly -- the point is to sit
// at the same specificity as the routes being replaced, so the physical default
// is never the most specific match again.
//
// Both families regardless of what the tunnel carries, because the alternative
// is the leak: see KillSwitchConfig. A host with no IPv6 at all is unaffected
// by two v6 routes that match nothing it sends.
func (k *KillSwitch) halves() []blackholeHalf {
	return []blackholeHalf{
		{prefix: "0.0.0.0/1"},
		{prefix: "128.0.0.0/1"},
		{prefix: "::/1", v6: true},
		{prefix: "8000::/1", v6: true},
	}
}

// RecoveryCommand is what an operator types to reopen a host by hand, for the
// case where veepin died without running its defers. It is logged when the
// switch engages rather than only when something goes wrong: the moment you
// need it is the moment you cannot reach the machine to look it up.
func (k *KillSwitch) RecoveryCommand() string {
	var parts []string
	for _, h := range k.halves() {
		parts = append(parts, "sudo "+strings.Join(h.del(), " "))
	}
	return strings.Join(parts, " ; ")
}
