// Package hostnet owns the host-side network setup a veepin server needs but
// deliberately does not perform by itself: assigning the TUN interface its
// address, bringing it up, enabling forwarding, and installing the NAT /
// FORWARD rules that let a tunnel subnet reach the WAN.
//
// It does this for both address families. The IPv6 half is the newer one and
// exists because it was missing: ikev2's server has always been able to hand a
// client an address out of its own IPv6 pool through config mode, and
// Server.Gateway6/Network6 were documented as being "for routing and NAT
// rules" while having no caller anywhere in the tree. The v6 gateway therefore
// never reached the interface -- the server could not answer a ping to its own
// tunnel address -- and a client's v6 traffic arrived at a host that would not
// forward it. Dual-stack worked inside the tunnel and stopped at its edge.
//
// It is the home of the behaviour behind `veepin serve -setup-nat`, extracted
// from cmd/veepin/serve.go so that both the single-protocol command and the
// supervisor in internal/supervisor build servers the same way.
//
// Every iptables rule the package installs is tagged with a comment it owns,
//
//	-m comment --comment veepin:<name>
//
// and Apply is idempotent: it never adds a rule that is already present, so
// rebuilding a listener (the supervisor's cold-rebuild path) re-runs Apply
// safely and leaves the host exactly as it found it. Teardown removes by the
// same comment, so a rebuilt or deleted listener takes its host state with it
// rather than accumulating MASQUERADE lines on every restart.
//
// The package shells out to ip/iptables/sysctl, which must be present and
// runnable with sufficient privileges (root, or CAP_NET_ADMIN on the binary).
package hostnet

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

// Comment is the iptables comment tag every rule Apply installs and Teardown
// removes. The <name> is the supervisor listener name, or "serve" for the
// single-protocol command so the two paths remain visually distinct from each
// other and from anything else on the host.
const Comment = "veepin"

// Commander runs an external command and returns its combined stdout/stderr.
// The default shells out via os/exec; tests inject a fake to assert on the
// exact sequence of commands without touching the host.
type Commander func(name string, args ...string) ([]byte, error)

// realCommander is the production commander: it is exactly what
// exec.Command(name, args...).CombinedOutput() does, just shaped so the same
// call works in tests.
func realCommander(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// ErrNoWAN reports that the interface was addressed and forwarding enabled, but
// no MASQUERADE rule was installed because Config.WAN was empty. The listener is
// serving and its clients can reach the host; they cannot reach anything beyond
// it.
//
// It is deliberately an error — the caller must not tell an operator that a
// tunnel carries traffic to the internet when it does not — and deliberately a
// distinguishable one, because it is equally not a reason to refuse to serve.
// Callers that can carry on should test errors.Is(err, ErrNoWAN) and log rather
// than abort; the supervisor does exactly that, so one listener missing its
// `wan` does not take the rest of the fleet down with it.
var ErrNoWAN = errors.New("hostnet: interface configured but no wan given, so no MASQUERADE installed")

// ErrNoIPv6 reports that the IPv4 half was configured and the IPv6 half was not,
// because the host has no usable ip6tables or has IPv6 disabled. The listener
// serves; its clients get a v6 address that reaches the host and nothing beyond
// it, exactly as they did before this package configured v6 at all.
//
// It is an error for the same reason ErrNoWAN is -- an operator must not be told
// a tunnel carries v6 when it does not -- and non-fatal for a reason ErrNoWAN
// does not have: ikev2's v6 pool is on by DEFAULT, so treating a missing
// ip6tables as fatal would stop every existing v4 deployment on a v6-less host
// from serving at all, over a capability its operator never asked for.
//
// Callers should test errors.Is(err, ErrNoIPv6) and log. Both the bare command
// and the supervisor do.
var ErrNoIPv6 = errors.New("hostnet: no usable ip6tables, so the tunnel's IPv6 half reaches the host only")

// Config is the host-network state for one listener.
type Config struct {
	// TUNName is the interface to bring up.
	TUNName string
	// Gateway is the server's in-tunnel address (the network end of the
	// tunnel subnet's first usable host).
	Gateway net.IP
	// Network is the tunnel subnet client addresses come from. Nil means a
	// layer-2 server (L2TPv3): no address to assign, no NAT to install.
	Network *net.IPNet
	// Gateway6 and Network6 are the IPv6 half, for a server that assigns an
	// address in both families (ikev2's dual-stack config mode). Both nil is
	// the ordinary v4-only case and installs no v6 state at all -- so a host
	// with no ip6tables is unaffected by this package unless a listener
	// actually hands out v6 addresses.
	//
	// They are separate fields rather than a slice of families because the two
	// are not interchangeable at the call site: a caller has a v4 pool, or a v4
	// and a v6 pool, and never a v6 pool alone. Nothing in the tree assigns v6
	// without v4.
	Gateway6 netip.Addr
	Network6 netip.Prefix
	// WAN is the upstream interface to masquerade behind. Empty means apply
	// the interface address and forwarding only; no MASQUERADE, and a non-nil
	// error is returned so the caller does not believe clients can reach the
	// internet when they cannot.
	WAN string
}

// MaskBits is the prefix length of the tunnel subnet, or 0 for a layer-2
// server. Lifted unchanged from serve.go so the nil-deref crash found by the
// L2TPv3 interop cell cannot come back.
func MaskBits(n *net.IPNet) int {
	if n == nil {
		return 0
	}
	ones, _ := n.Mask.Size()
	return ones
}

// State is the record of what Apply installed for one listener, sufficient for
// a later Teardown to remove exactly that. It is deliberately not the caller's
// current Config: the listener's config may have been edited since (WAN dropped,
// address changed), and a TUN name the kernel assigned is present only in the
// State, never in the listener's options. The caller persists it -- the
// supervisor writes <config>/mgmt/hostnet/<name>.json after Apply and reads it
// back on teardown -- so teardown is the inverse of what actually happened, not
// of what the config file now says.
type State struct {
	// TUNName is the interface the rules name. Kernel-assigned names ("tun0")
	// live only here once the server that owned them is closed.
	TUNName string `json:"tun"`
	// WAN is the interface MASQUERADE was installed for; empty means nothing
	// rule-shaped was installed.
	WAN string `json:"wan,omitempty"`
	// Network is the tunnel subnet the MASQUERADE source selector names, in
	// CIDR form; empty for a layer-2 server, which installs no rules.
	Network string `json:"network,omitempty"`
	// Network6 is the same for the IPv6 half, empty when the listener assigned
	// no v6 addresses. It is recorded separately so a listener that gained or
	// lost its v6 pool since Apply still tears down what was actually
	// installed -- the reason State exists at all.
	Network6 string `json:"network6,omitempty"`
}

// State returns the record a Teardown needs for the config Apply is about to
// install.
func (c Config) State() State {
	st := State{TUNName: c.TUNName, WAN: c.WAN}
	if c.Network != nil {
		st.Network = c.Network.String()
	}
	if c.Network6.IsValid() {
		st.Network6 = c.Network6.String()
	}
	return st
}

// Apply configures the TUN address, brings the interface up, enables IPv4
// forwarding, and installs tagged MASQUERADE/FORWARD rules if a WAN was given.
// It is idempotent: every iptables rule it adds is checked first so a second
// call for the same listener leaves the host unchanged.
func Apply(name string, cfg Config) error {
	return applyWith(name, cfg, realCommander)
}

// Teardown removes every host-side rule tagged for name, in reverse of Apply's
// order. It is bounded (at most 64 deletes per chain) so a runaway rule list
// cannot hang the supervisor; a healthy host has one row per listener.
//
// It derives the teardown set from cfg, which is correct for the bare command
// (whose config cannot have changed while it was running) and for tests. A
// caller that manages a fleet -- the supervisor -- must not do that: the
// listener's config may have been edited, or its TUN name kernel-assigned, so
// it persists the State that Apply installed and tears down from that instead.
// See TeardownState.
func Teardown(name string, cfg Config) error {
	return TeardownState(name, cfg.State())
}

// TeardownState is the persisted-state form of Teardown: it removes exactly the
// rules the recorded State describes, whether or not the listener's current
// config still matches. A State with an empty WAN or Network (no NAT was ever
// installed) is a no-op.
func TeardownState(name string, st State) error {
	return teardownStateWith(name, st, realCommander)
}

// ApplyWithName is Apply using an explicit commander. It exists for tests; non-
// test callers use Apply, which picks the real os/exec commander.
func ApplyWithName(name string, cfg Config, run Commander) error {
	return applyWith(name, cfg, run)
}

// TeardownWithName is Teardown using an explicit commander.
func TeardownWithName(name string, cfg Config, run Commander) error {
	return TeardownStateWithName(name, cfg.State(), run)
}

// TeardownStateWithName is TeardownState using an explicit commander.
func TeardownStateWithName(name string, st State, run Commander) error {
	return teardownStateWith(name, st, run)
}

func applyWith(name string, cfg Config, run Commander) error {
	if cfg.TUNName == "" {
		return errors.New("hostnet: TUNName is required")
	}

	// A layer-2 server (L2TPv3) has no tunnel subnet, so there is no address to
	// assign and no NAT to install -- the operator owns bridging and addressing.
	// The interface still has to come up, though, or the pseudowire carries
	// nothing: an earlier version returned here before the link-up below and
	// left the interface DOWN while reporting success.
	if cfg.Network == nil {
		if out, err := run("ip", "link", "set", cfg.TUNName, "up"); err != nil {
			return fmt.Errorf("hostnet: ip link set %s up: %v: %s",
				cfg.TUNName, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	bits := MaskBits(cfg.Network)

	// `ip addr add` is not idempotent: re-adding an address the interface
	// already holds fails with "File exists". Re-running Apply on a rebuild
	// would surface that as an error and the supervisor would refuse a benign
	// restart. Treat "already there" as success.
	addr := fmt.Sprintf("%s/%d", cfg.Gateway, bits)
	if out, err := run("ip", "addr", "add", addr, "dev", cfg.TUNName); err != nil {
		if !isAlreadyExists(out) {
			return fmt.Errorf("hostnet: ip addr add %s dev %s: %v: %s",
				addr, cfg.TUNName, err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := run("ip", "link", "set", cfg.TUNName, "up"); err != nil {
		return fmt.Errorf("hostnet: ip link set %s up: %v: %s",
			cfg.TUNName, err, strings.TrimSpace(string(out)))
	}
	// Advisory, deliberately: forwarding is host-wide, so a previous veepin
	// instance or another VPN daemon may already own it, and failing here would
	// make a shared host unable to start any listener once it had been set. The
	// branch that discarded the output was doing exactly this, at more length.
	_, _ = run("sysctl", "-w", "net.ipv4.ip_forward=1")

	// The IPv6 half, when the listener assigns v6 addresses too. It mirrors the
	// v4 setup exactly, one command name over -- which is the whole reason it
	// was cheap to add and no reason at all that it was absent.
	//
	// v6 is degraded rather than fatal: see ErrNoIPv6. The v4 half is already
	// installed by the time this runs, so a host that cannot do v6 keeps the
	// tunnel it had.
	v6 := cfg.Network6
	var v6err error
	if v6.IsValid() {
		if err := applyIPv6(run, cfg); err != nil {
			v6, v6err = netip.Prefix{}, err
		}
	}

	tag := comment(name)
	if cfg.WAN != "" {
		for _, f := range families(cfg.Network, v6) {
			if err := ensureNAT(run, f, tag, cfg.TUNName, cfg.WAN); err != nil {
				if f.bin == "ip6tables" {
					// Same degradation: the v4 rules are in, and a v6 rule that
					// will not install is not a reason to refuse the listener.
					v6err = fmt.Errorf("%w: %w", ErrNoIPv6, err)
					continue
				}
				return err
			}
		}
		return v6err
	}
	// No WAN named: the interface has an address and forwarding, but nothing
	// leaves it. Report it, so neither the supervisor nor the bare command
	// advertises a tunnel that reaches the internet when it does not -- but
	// report it as ErrNoWAN, which a caller can recognise and carry on from.
	//
	// Joined with any v6 failure rather than replacing it: both are "configured,
	// but does not reach everything", and a caller testing errors.Is for either
	// still finds it.
	if v6err != nil {
		return errors.Join(ErrNoWAN, v6err)
	}
	return ErrNoWAN
}

// applyIPv6 puts the v6 gateway on the interface and enables v6 forwarding.
//
// It probes ip6tables first, because that is the command whose absence must be
// reported as ErrNoIPv6 rather than as a failure of the listener, and probing is
// clearer than inferring it from whichever rule happened to be installed first.
// `-S` on a chain changes nothing, which is what makes it usable as a probe.
func applyIPv6(run Commander, cfg Config) error {
	if out, err := run("ip6tables", "-t", "nat", "-S", "POSTROUTING"); err != nil {
		return fmt.Errorf("%w: ip6tables: %v: %s", ErrNoIPv6, err, strings.TrimSpace(string(out)))
	}
	addr6 := fmt.Sprintf("%s/%d", cfg.Gateway6, cfg.Network6.Bits())
	if out, err := run("ip", "-6", "addr", "add", addr6, "dev", cfg.TUNName); err != nil {
		if !isAlreadyExists(out) {
			return fmt.Errorf("%w: ip -6 addr add %s dev %s: %v: %s",
				ErrNoIPv6, addr6, cfg.TUNName, err, strings.TrimSpace(string(out)))
		}
	}
	// Advisory for the same reason as the v4 sysctl: forwarding is host-wide,
	// so another daemon may already own it, and a container may not permit
	// writing it at all.
	_, _ = run("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	return nil
}

// family pairs an address family's rule binary with the tunnel subnet its
// MASQUERADE selector names. Nothing else about the two differs, which is why
// the rest of this package treats them identically.
type family struct {
	bin     string // iptables or ip6tables
	network string // the subnet in CIDR form
}

// families returns the families a listener installed rules for, in the order
// they are applied and the reverse of the order they are torn down. A nil
// network contributes nothing, so a v4-only listener never names ip6tables and
// a host without it is unaffected.
func families(v4 *net.IPNet, v6 netip.Prefix) []family {
	var out []family
	if v4 != nil {
		out = append(out, family{bin: "iptables", network: v4.String()})
	}
	if v6.IsValid() {
		out = append(out, family{bin: "ip6tables", network: v6.String()})
	}
	return out
}

// familiesFromState is families for a recorded State, whose networks are
// already strings.
func familiesFromState(st State) []family {
	var out []family
	if st.Network != "" {
		out = append(out, family{bin: "iptables", network: st.Network})
	}
	if st.Network6 != "" {
		out = append(out, family{bin: "ip6tables", network: st.Network6})
	}
	return out
}

// natRules is the three rules one family needs: MASQUERADE out of the WAN, and
// FORWARD accept in both directions on the tunnel interface. Built in one place
// so apply and teardown cannot drift, which is how a rule survives a teardown
// that thought it had removed it.
func natRules(f family, tag, tun, wan string) [][]string {
	return [][]string{
		{"-t", "nat", "-A", "POSTROUTING", "-s", f.network, "-o", wan,
			"-j", "MASQUERADE", "-m", "comment", "--comment", tag},
		{"-A", "FORWARD", "-i", tun, "-j", "ACCEPT", "-m", "comment", "--comment", tag},
		{"-A", "FORWARD", "-o", tun, "-j", "ACCEPT", "-m", "comment", "--comment", tag},
	}
}

// natRuleNames labels each rule for the error message, in natRules' order.
var natRuleNames = [...]string{"NAT MASQUERADE", "FORWARD in", "FORWARD out"}

func ensureNAT(run Commander, f family, tag, tun, wan string) error {
	for i, rule := range natRules(f, tag, tun, wan) {
		if err := ensureRule(run, f.bin, rule); err != nil {
			return fmt.Errorf("hostnet: %s (%s): %w", natRuleNames[i], f.bin, err)
		}
	}
	return nil
}

func removeNAT(run Commander, f family, tag, tun, wan string) error {
	for i, rule := range natRules(f, tag, tun, wan) {
		if err := removeRule(run, f.bin, rule); err != nil {
			return fmt.Errorf("hostnet: %s teardown (%s): %w", natRuleNames[i], f.bin, err)
		}
	}
	return nil
}

// teardownStateWith deletes the rules the recorded State describes, using the
// given commander. A State with no WAN or no Network installed nothing
// rule-shaped, so teardown is a no-op -- the layer-2 path (Network empty) and
// the no-WAN path (ErrNoWAN from Apply) both land here. Teardown is safe to
// call unconditionally for any listener.
func teardownStateWith(name string, st State, run Commander) error {
	if st.WAN == "" {
		return nil
	}
	tag := comment(name)
	// Reverse of the order Apply installs them, so a partially-torn-down host
	// never has v6 rules pointing at an interface whose v4 rules are gone.
	fams := familiesFromState(st)
	for i := len(fams) - 1; i >= 0; i-- {
		if err := removeNAT(run, fams[i], tag, st.TUNName, st.WAN); err != nil {
			return err
		}
	}
	return nil
}

// TeardownByTag removes every rule carrying this listener's comment tag,
// whatever its other fields say. It is the recovery path for when the recorded
// State is missing or unreadable: the tag is the one thing every rule Apply
// installs is guaranteed to carry, so it can find them when nothing else can.
//
// Deliberately not the normal path. TeardownState names the exact rules it
// expects and fails loudly if the host disagrees; this one deletes whatever it
// finds under the tag, which is right for recovery and too blunt for routine
// use.
func TeardownByTag(name string) error {
	return teardownByTagWith(name, realCommander)
}

// TeardownByTagWithName is TeardownByTag using an explicit commander.
func TeardownByTagWithName(name string, run Commander) error {
	return teardownByTagWith(name, run)
}

func teardownByTagWith(name string, run Commander) error {
	tag := comment(name)
	// Both families, because the recovery path cannot know which the listener
	// used -- that is precisely the information it has lost. A host without
	// ip6tables answers with an error, which the `continue` below already
	// treats as "nothing of ours here".
	for _, c := range []struct{ bin, table, chain string }{
		{"iptables", "nat", "POSTROUTING"},
		{"iptables", "filter", "FORWARD"},
		{"ip6tables", "nat", "POSTROUTING"},
		{"ip6tables", "filter", "FORWARD"},
	} {
		out, err := run(c.bin, "-t", c.table, "-S", c.chain)
		if err != nil {
			// A chain that does not exist is not an error worth failing on: the
			// host simply has nothing of ours in it.
			continue
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[0] != "-A" || !ruleHasTag(fields, tag) {
				continue
			}
			// Unquoted, because `iptables -S` prints the comment quoted --
			// `--comment "veepin:site-a"` -- and there is no shell between here
			// and execve to take the quotes off. Passing them through made every
			// -D name a comment no installed rule has, so each one failed, the
			// loop returned on the first, and the rules stayed on the host
			// forever. ruleHasTag below already knew to unquote to MATCH; only
			// the rebuild did not.
			args := append([]string{"-t", c.table}, unquoteFields(fields)...)
			args[2] = "-D"
			if o, derr := run(c.bin, args...); derr != nil {
				return fmt.Errorf("hostnet: tagged teardown: %s %s: %v: %s",
					c.bin, strings.Join(args, " "), derr, strings.TrimSpace(string(o)))
			}
		}
	}
	return nil
}

// unquoteFields strips the double quotes `iptables -S` puts around values that
// contain spaces (in practice, the comment). exec.Command passes each argument
// through untouched, so a quote that survives here is a literal quote in the
// value iptables compares against.
func unquoteFields(fields []string) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = strings.Trim(f, `"`)
	}
	return out
}

// ruleHasTag reports whether an `iptables -S` rule carries exactly this tag as
// its comment. Compared field-by-field rather than by substring so the tag for
// "site-a" does not match the rule belonging to "site-ab".
func ruleHasTag(fields []string, tag string) bool {
	for i, f := range fields {
		if f != "--comment" || i+1 >= len(fields) {
			continue
		}
		if strings.Trim(fields[i+1], `"`) == tag {
			return true
		}
	}
	return false
}

// ensureRule adds rule to iptables if it is not already there. The check uses
// `iptables -C` (does this rule exist?), the standard idempotent pattern.
func ensureRule(run Commander, bin string, rule []string) error {
	if _, err := run(bin, iptablesCheckArgs(rule)...); err == nil {
		return nil // rule already exists
	}
	// rule is already in -A form, so it is passed straight through. It went via
	// an iptablesMutateArgs helper that copied the slice and returned it
	// unchanged, described by its own comment as "a place to swap operations
	// later" -- a hook for a caller that never arrived.
	if out, err := run(bin, rule...); err != nil {
		return fmt.Errorf("%s %s: %v: %s",
			bin, strings.Join(rule, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeRule deletes rule(s) from iptables, looping while a matching rule still
// exists so duplicate installs (should be impossible with ensureRule, but
// defensive) do not survive teardown.
func removeRule(run Commander, bin string, rule []string) error {
	deleteArgs := iptablesDeleteArgs(rule)
	for range 64 {
		checkArgs := iptablesCheckArgs(rule)
		if _, err := run(bin, checkArgs...); err != nil {
			return nil // no matching rule left
		}
		if out, err := run(bin, deleteArgs...); err != nil {
			return fmt.Errorf("%s %s: %v: %s",
				bin, strings.Join(deleteArgs, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// iptablesCheckArgs swaps the operation token (-A / -D) in rule for -C, which
// tests whether a matching rule exists without adding or removing anything.
func iptablesCheckArgs(rule []string) []string {
	return swapOp(rule, "-C")
}

// iptablesDeleteArgs swaps the operation token (-A) in rule for -D.
func iptablesDeleteArgs(rule []string) []string {
	return swapOp(rule, "-D")
}

// swapOp returns rule with the first occurrence of "-A" replaced by op. The same
// helper handles -C and -D: the rule slice's structure is "[-t table] -A CHAIN
// ..." and only the -A changes between add/check/delete.
func swapOp(rule []string, op string) []string {
	out := make([]string, len(rule))
	copy(out, rule)
	for i, a := range out {
		if a == "-A" || a == "-D" {
			out[i] = op
			return out
		}
	}
	return out
}

// isAlreadyExists recognises `ip addr add`'s "File exists" / "RTNETLINK:
// File exists" so a re-application on a rebuilt interface is treated as a
// no-op rather than an error.
func isAlreadyExists(out []byte) bool {
	return strings.Contains(string(out), "File exists")
}

// comment is the verbatim value written to iptables -m comment --comment. The
// tag is the literal "veepin:<name>" so host iptables -L output reads as one
// recognizable cluster per listener.
func comment(name string) string {
	return Comment + ":" + name
}
