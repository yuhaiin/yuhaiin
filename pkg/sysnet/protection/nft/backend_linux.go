//go:build linux && !android

package nft

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
)

// Fixed locations.
const (
	StateDir  = "/var/lib/yuhaiin/protection"
	StateFile = StateDir + "/state.json"
	UnitName  = "yuhaiin-protection.service"
	UnitPath  = "/etc/systemd/system/" + UnitName
)

// The boot unit restores protection before the network comes up
// (network-pre.target), so nothing leaks before Yuhaiin starts.
const unitTemplate = `[Unit]
Description=Yuhaiin Network Protection (kill switch) at startup
Documentation=https://github.com/yuhaiin/yuhaiin/blob/main/docs/network-protection.md
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=%s protection restore
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
`

// Backend applies the policy with nftables from the Yuhaiin process (which
// runs as root). The rules live in the kernel: they stay when Yuhaiin exits,
// and a systemd unit loads them again at boot.
type Backend struct {
	// OwnMark returns the socket mark of Yuhaiin's sockets (0 when the
	// sockets are not marked).
	OwnMark func() uint32

	mu        sync.Mutex
	applied   string
	tunnels   []Tunnel
	own       bool
	session   uint64
	updatedAt int64
	lastErr   error
}

// NewBackend returns the Linux backend.
func NewBackend(ownMark func() uint32) *Backend { return &Backend{OwnMark: ownMark, session: 1} }

func (b *Backend) Session() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.session
}

// PrepareProcess reports whether Yuhaiin's sockets carry the mark the kill
// switch lets through.
func (b *Backend) PrepareProcess(sysnet.ProtectionStatus) (bool, string) {
	if b.OwnMark != nil && b.OwnMark() != 0 {
		return true, ""
	}
	return false, "Yuhaiin's sockets are not marked (it needs CAP_NET_ADMIN)"
}

func (b *Backend) Close() error { return nil }

func (b *Backend) resolve(p protection.Policy) Env {
	env := Env{}
	for _, t := range p.Tunnels {
		if ifc, err := net.InterfaceByName(t.Name); err == nil {
			env.Tunnels = append(env.Tunnels, Tunnel{Name: t.Name, Index: ifc.Index})
		}
	}
	if p.OwnTraffic && b.OwnMark != nil {
		env.OwnMark = b.OwnMark()
	}
	return env
}

func (b *Backend) apply(p protection.Policy) error {
	env := b.resolve(p)
	plan, err := Compile(p, env)
	if err != nil {
		return protection.Problem(sysnet.ProblemRulesRejected, "The policy was rejected: "+err.Error(), "The previous rules stay in force")
	}
	if err := Apply(plan); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return protection.Problem(sysnet.ProblemPermission, "Loading nftables rules needs CAP_NET_ADMIN: "+err.Error(), "Run Yuhaiin as root (sudo yuhaiin install)")
		}
		return protection.Problem(sysnet.ProblemRulesRejected, "nftables rejected the protection table: "+err.Error(), "The previous rules stay in force")
	}
	b.applied, b.tunnels, b.own = plan.ID, env.Tunnels, env.OwnMark != 0
	b.updatedAt = time.Now().Unix()
	return nil
}

func (b *Backend) Enable(ctx context.Context, p protection.Policy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := p.Validate(); err != nil {
		return protection.Problem(sysnet.ProblemRulesRejected, "The policy was rejected: "+err.Error(), "")
	}
	state, _, _ := helper.LoadState(StateFile)
	state.Enabled, state.StartAtBoot, state.ChangedBy, state.UpdatedAt = true, p.StartAtBoot, "api", time.Now().Unix()
	state.Policy = p.Persistent().Normalize()
	if err := helper.SaveState(StateFile, state); err != nil {
		return protection.Problem(sysnet.ProblemState, "Cannot save the protection state: "+err.Error(), "Nothing was changed")
	}
	if err := b.apply(p); err != nil {
		b.lastErr = err
		return err
	}
	b.lastErr = setBootUnit(ctx, p.StartAtBoot)
	return nil
}

func (b *Backend) Update(ctx context.Context, p protection.Policy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, _, err := helper.LoadState(StateFile)
	if err != nil || !state.Enabled {
		return err
	}
	persistent := p.Persistent().Normalize()
	if persistent.Fingerprint() != state.Policy.Fingerprint() {
		state.Policy, state.UpdatedAt = persistent, time.Now().Unix()
		if err := helper.SaveState(StateFile, state); err != nil {
			return protection.Problem(sysnet.ProblemState, "Cannot save the protection state: "+err.Error(), "")
		}
	}
	p.StartAtBoot = state.StartAtBoot
	b.lastErr = b.apply(p)
	return b.lastErr
}

// Disable saves the disabled state first, then removes the table.
func (b *Backend) Disable(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, _, _ := helper.LoadState(StateFile)
	state.Enabled, state.ChangedBy, state.UpdatedAt = false, "api", time.Now().Unix()
	if err := helper.SaveState(StateFile, state); err != nil {
		return protection.Problem(sysnet.ProblemState, "Cannot save the disabled state, so protection was left on: "+err.Error(),
			"Try: sudo yuhaiin protection disable --recovery")
	}
	err := Remove()
	b.applied, b.tunnels, b.own = "", nil, false
	return errors.Join(err, setBootUnit(ctx, false))
}

func (b *Backend) Status(ctx context.Context) (sysnet.ProtectionStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, _, stateErr := helper.LoadState(StateFile)
	in := Inspect()
	st := Describe(in, state, stateErr)
	st.Service = ""
	st.UpdatedAt = b.updatedAt
	loaded := LoadedID(labels(in))
	if state.Enabled && stateErr == nil {
		if !st.Effective || (b.applied != "" && loaded != b.applied) {
			// Missing or changed by another program: apply again on the
			// controller's next sync.
			if b.applied != "" {
				st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemModified,
					Message: "The protection table was removed or changed by another program; it is restored"})
			}
			b.session++
			b.applied = ""
		}
	}
	if st.Effective {
		for _, t := range b.tunnels {
			st.TunnelInterfaces = append(st.TunnelInterfaces, t.Name)
		}
		st.OwnTraffic.Allowed = b.own
	}
	st.OwnTraffic.Method = "socket_mark"
	if b.OwnMark != nil && b.OwnMark() != 0 {
		st.OwnTraffic.Group = fmt.Sprintf("mark %#x", b.OwnMark())
	} else {
		st.OwnTraffic.Reason = "Yuhaiin's sockets are not marked (it needs CAP_NET_ADMIN)"
	}
	if ifaces, err := iface.List(); err == nil {
		for _, i := range ifaces {
			if i.Up && i.Type != iface.TypeLoopback && !strings.EqualFold(i.Name, "lo") && !containsTunnel(b.tunnels, i.Name) {
				st.PhysicalInterfaces = append(st.PhysicalInterfaces, i.Name)
			}
		}
	}
	if b.lastErr != nil && state.Enabled {
		p := problemOf(b.lastErr)
		st.Problems = append(st.Problems, p)
		st.Error = p.Message
		if st.State == sysnet.ProtectionProtected {
			st.State = sysnet.ProtectionDegraded
		}
	}
	if st.State == sysnet.ProtectionProtected && !b.own && b.applied != "" && len(b.tunnels) > 0 {
		st.State = sysnet.ProtectionDegraded
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemOwnTraffic,
			Message: "Yuhaiin's own connections are blocked: " + st.OwnTraffic.Reason, Hint: "Run Yuhaiin as root (sudo yuhaiin install)"})
	}
	if state.Enabled && state.StartAtBoot && !bootUnitEnabled(ctx) {
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemBootstrap,
			Message: "Protection is not restored at startup: the " + UnitName + " systemd unit is not enabled", Hint: "Protection returns when Yuhaiin starts"})
	}
	st.CheckedAt = time.Now().Unix()
	return st, nil
}

func containsTunnel(list []Tunnel, name string) bool {
	for _, t := range list {
		if t.Name == name {
			return true
		}
	}
	return false
}

func problemOf(err error) sysnet.ProtectionProblem {
	if p, ok := errors.AsType[*protection.ProblemError](err); ok {
		return p.Problem
	}
	return sysnet.ProtectionProblem{Code: sysnet.ProblemPolicySync, Message: err.Error()}
}

func labels(in State) []string {
	out := make([]string, len(in.Rules))
	for i, r := range in.Rules {
		out[i] = r.Label
	}
	return out
}

// Describe turns the kernel state and the saved state into a status.
func Describe(in State, state helper.State, stateErr error) sysnet.ProtectionStatus {
	st := protection.UnsupportedStatus()
	st.Supported, st.Backend, st.BackendName, st.Mode = true, "nftables", "Linux nftables", sysnet.ProtectionModeStandard
	st.Desired = sysnet.ProtectionSettings{Enabled: state.Enabled, StartAtBoot: state.StartAtBoot}
	st.Filter.Name = "inet " + Table
	loaded := ""
	if in.Known {
		on := true // nftables needs no switch: a loaded table is enforced
		st.Filter.Enabled = &on
		loaded = LoadedID(labels(in))
		has := loaded != ""
		st.Filter.Registered, st.Filter.Loaded = &has, &has
	}
	if in.Err != nil {
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemPolicySync, Message: "Reading nftables failed: " + in.Err.Error()})
	}
	if loaded != "" {
		st.PrivateNetworks = protection.PrefixStrings(state.Policy.PrivateNetworks, 1000)
		st.BypassNetworks = protection.PrefixStrings(state.Policy.BypassNetworks, 500)
		st.BypassCount = len(state.Policy.BypassNetworks)
		var blocked sysnet.ProtectionCounters
		for _, r := range in.Rules {
			if Category(r.Label) == sysnet.RuleBlock {
				blocked.Packets += r.Packets
				blocked.Bytes += r.Bytes
			}
		}
		st.Blocked = &blocked
	}
	st.Effective = loaded != ""
	if stateErr != nil {
		st.Error = stateErr.Error()
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemState, Message: stateErr.Error(),
			Hint: "Enable protection again from Yuhaiin, or run: sudo yuhaiin protection disable --recovery"})
	}
	switch {
	case stateErr != nil:
		st.State = sysnet.ProtectionError
	case !state.Enabled && loaded == "":
		st.State = sysnet.ProtectionDisabled
	case !state.Enabled:
		st.State = sysnet.ProtectionError
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemModified, Message: "Protection is disabled but its rules are still loaded",
			Hint: "Run: sudo yuhaiin protection disable --recovery"})
	case !st.Effective:
		st.State = sysnet.ProtectionError
	default:
		st.State = sysnet.ProtectionProtected
	}
	return st
}

// systemd reports whether systemd manages this system.
func systemd() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

func systemctl(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	return string(out), err
}

func bootUnitEnabled(ctx context.Context) bool {
	if !systemd() {
		return false
	}
	out, err := systemctl(ctx, "is-enabled", UnitName)
	return err == nil && strings.TrimSpace(out) == "enabled"
}

// setBootUnit installs and enables (or disables) the unit that restores
// protection at boot. Without systemd it reports that protection returns
// only when Yuhaiin starts.
func setBootUnit(ctx context.Context, on bool) error {
	if !systemd() {
		if on {
			return protection.Problem(sysnet.ProblemBootstrap, "This system does not use systemd; protection is restored when Yuhaiin starts, not at boot", "")
		}
		return nil
	}
	if !on {
		if _, err := os.Stat(UnitPath); err != nil {
			return nil
		}
		if out, err := systemctl(ctx, "disable", UnitName); err != nil {
			return fmt.Errorf("systemctl disable %s: %w: %s", UnitName, err, strings.TrimSpace(out))
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	want := fmt.Sprintf(unitTemplate, exe)
	if current, _ := os.ReadFile(UnitPath); string(current) != want {
		if err := os.WriteFile(UnitPath, []byte(want), 0o644); err != nil {
			return fmt.Errorf("install %s: %w", UnitPath, err)
		}
		_, _ = systemctl(ctx, "daemon-reload")
	}
	if out, err := systemctl(ctx, "enable", UnitName); err != nil {
		return fmt.Errorf("systemctl enable %s: %w: %s", UnitName, err, strings.TrimSpace(out))
	}
	return nil
}

// RestoreAtBoot loads the saved persistent policy (no TUNs, no Yuhaiin
// traffic: Yuhaiin is not running yet). It runs from the boot unit.
func RestoreAtBoot() error {
	state, _, err := helper.LoadState(StateFile)
	if err != nil {
		// Damaged state fails closed: private networks only.
		log.Error("network protection: saved state is damaged; blocking with only private networks allowed", "err", err)
		state = helper.State{Enabled: true, StartAtBoot: true, Policy: protection.Policy{Mode: sysnet.ProtectionModeStandard}}
		state.Policy.PrivateNetworks = defaultPrivate()
	}
	if !state.Enabled || !state.StartAtBoot {
		return nil
	}
	p := state.Policy
	p.Mode = sysnet.ProtectionModeStandard
	plan, err := Compile(p, Env{})
	if err != nil {
		return err
	}
	return Apply(plan)
}

// Rules reads the rules view (read-only).
func (b *Backend) Rules(ctx context.Context) sysnet.ProtectionRules {
	b.mu.Lock()
	state, _, _ := helper.LoadState(StateFile)
	p := state.Policy
	p.Mode = sysnet.ProtectionModeStandard
	tunnels, own := b.tunnels, b.own
	b.mu.Unlock()
	if len(tunnels) > 0 {
		for _, t := range tunnels {
			p.Tunnels = append(p.Tunnels, protection.Tunnel{Name: t.Name})
		}
	}
	p.OwnTraffic = own
	env := Env{Tunnels: tunnels}
	if own && b.OwnMark != nil {
		env.OwnMark = b.OwnMark()
	}
	plan, _ := Compile(p, env)
	return Snapshot(ctx, plan)
}
