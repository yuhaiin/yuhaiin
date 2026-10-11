//go:build !linux

package dataplane

import (
	"fmt"
	"net"
	"runtime"
)

// The kill switch off Linux: refused, and the refusal says why rather than
// pretending.
//
// The Linux implementation installs the same two /1 halves ClientRouter uses,
// as blackholes at a worse metric, so they sit inert while the tunnel is up and
// take over the instant the kernel drops the TUN's routes with its device. That
// handover — with no window — is the whole property, and it depends on two
// things the BSD routing table does not offer: a blackhole route type, and per-
// route metrics that let two routes for one prefix coexist and be ordered.
//
// macOS has `route -n add -blackhole`, but no metric to sit it behind the
// tunnel's own route, so arming it while the tunnel is healthy is not possible
// and arming it on teardown leaves however long the teardown takes as
// plaintext.
//
// # Why the pf answer is also declined, concretely
//
// The obvious alternative is a pf anchor, and it was surveyed rather than waved
// at. `pfctl -a veepin -f -` loads rules into an anchor happily — and pf never
// evaluates them, because an anchor is only consulted if the ACTIVE ruleset
// references it, and macOS's stock /etc/pf.conf hooks only `com.apple/*`. There
// is no generic anchor to attach to.
//
// So making it work means one of two things, and both are the promise this
// project declines rather than a detail of it:
//
//   - Edit /etc/pf.conf to add `anchor "veepin"`, permanently, on the user's
//     host.
//   - Or replace the active ruleset with one that includes ours and restore the
//     old one afterwards, which means veepin owns the machine's entire firewall
//     for the life of the tunnel and leaves it in whatever state a crash finds.
//
// The second also fails in the wrong direction: a crash leaves the anchor
// referenced and empty, so traffic flows — a kill switch that fails open is
// worse than no kill switch, because the operator believes they have one.
//
// And it would ship unverified. Nobody has run this client on macOS hardware at
// all (doc/verifying-macos.md is the procedure and it is still owed), so this
// would be an untested firewall manipulator able to lock a user out of their
// own machine. That is not a trade to make sight-unseen.
//
// doc/verifying-macos.md carries a pf recipe an operator can install
// themselves, which is the right shape: the same protection, chosen and owned
// by the person whose firewall it is.
//
// So this returns an error naming the platform, and cmd/veepin treats it as the
// permanent configuration failure it is: the operator asked for something this
// platform cannot give them, and being told is better than being told nothing
// and believing they have it.

// KillSwitchConfig is the same shape as the Linux one, so the caller compiles
// everywhere and the refusal happens at run time with a message rather than at
// build time with a missing symbol.
type KillSwitchConfig struct {
	ServerIP net.IP
	V4, V6   bool
}

// KillSwitch is the unsupported stub.
type KillSwitch struct{ cfg KillSwitchConfig }

// NewKillSwitch creates a switch that will refuse to engage.
func NewKillSwitch(cfg KillSwitchConfig) *KillSwitch { return &KillSwitch{cfg: cfg} }

// Engaged is always false: nothing was ever installed.
func (k *KillSwitch) Engaged() bool { return false }

// Engage refuses, naming the platform and what it would take.
func (k *KillSwitch) Engage() error {
	return fmt.Errorf("kill switch: not supported on %s — it needs blackhole routes with "+
		"per-route metrics, which the BSD routing table does not have. A pf anchor would "+
		"work but only if the active ruleset references it, which means editing "+
		"/etc/pf.conf or replacing your whole ruleset; veepin will not do either to your "+
		"host. Drop -kill-switch, or install the pf rules yourself — "+
		"doc/verifying-macos.md has a recipe", runtime.GOOS)
}

// Disengage is a no-op: Engage never succeeded.
func (k *KillSwitch) Disengage() error { return nil }

// RecoveryCommand is empty, since nothing needs recovering.
func (k *KillSwitch) RecoveryCommand() string { return "" }
