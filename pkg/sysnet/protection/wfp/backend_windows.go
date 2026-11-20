//go:build windows

package wfp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// StateDir is where the saved state lives; only SYSTEM and Administrators
// may read or change it.
func StateDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "yuhaiin", "protection")
}

func stateFile() string { return filepath.Join(StateDir(), "state.json") }

// secureDir creates dir with an ACL for SYSTEM and Administrators only, so
// an unprivileged user cannot turn protection off through the state file.
func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func saveState(s helper.State) error {
	if err := secureDir(StateDir()); err != nil {
		return err
	}
	return helper.SaveState(stateFile(), s)
}

// Elevated reports whether the process runs with administrator rights.
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// Backend applies the policy with WFP from the Yuhaiin process (a service
// running as LocalSystem).
type Backend struct {
	mu        sync.Mutex
	engine    *Engine
	app       string
	applied   string
	tunnels   []Tunnel
	own       bool
	session   uint64
	updatedAt int64
	lastErr   error
}

// NewBackend returns the Windows backend; it connects to WFP on first use.
func NewBackend() *Backend {
	app, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(app); err == nil {
		app = resolved
	}
	return &Backend{app: app, session: 1}
}

func (b *Backend) open() (*Engine, error) {
	if b.engine != nil {
		return b.engine, nil
	}
	if !Elevated() {
		return nil, protection.Problem(sysnet.ProblemPermission, "Network Protection needs administrator rights", "Run Yuhaiin as the Windows service (yuhaiin install)")
	}
	e, err := Open()
	if err != nil {
		return nil, err
	}
	b.engine = e
	return e, nil
}

func (b *Backend) Session() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.session
}

// PrepareProcess: Yuhaiin's executable is permitted by its application ID.
func (b *Backend) PrepareProcess(sysnet.ProtectionStatus) (bool, string) { return b.app != "", "" }

// Close ends the dynamic session: Windows removes the TUN and Yuhaiin
// permits, the baseline stays.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.engine == nil {
		return nil
	}
	err := b.engine.Close()
	b.engine = nil
	return err
}

func (b *Backend) resolve(p protection.Policy) Env {
	env := Env{}
	if p.OwnTraffic {
		env.App = b.app
	}
	ifaces, _ := iface.List()
	for _, t := range p.Tunnels {
		for _, i := range ifaces {
			if i.Name == t.Name {
				if luid, err := winipcfg.LUIDFromIndex(uint32(i.Index)); err == nil {
					env.Tunnels = append(env.Tunnels, Tunnel{Name: t.Name, LUID: uint64(luid)})
				}
			}
		}
	}
	return env
}

func (b *Backend) apply(p protection.Policy) error {
	e, err := b.open()
	if err != nil {
		return err
	}
	env := b.resolve(p)
	plan, err := Compile(p, env)
	if err != nil {
		return protection.Problem(sysnet.ProblemRulesRejected, "The policy was rejected: "+err.Error(), "The previous filters stay in force")
	}
	if err := e.Apply(plan); err != nil {
		return protection.Problem(sysnet.ProblemRulesRejected, "The Windows Filtering Platform rejected the protection filters: "+err.Error(), "The previous filters stay in force")
	}
	b.applied, b.tunnels, b.own = plan.ID, env.Tunnels, env.App != ""
	b.updatedAt = time.Now().Unix()
	return nil
}

func (b *Backend) Enable(ctx context.Context, p protection.Policy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := p.Validate(); err != nil {
		return protection.Problem(sysnet.ProblemRulesRejected, "The policy was rejected: "+err.Error(), "")
	}
	if _, err := b.open(); err != nil {
		return err
	}
	state, _, _ := helper.LoadState(stateFile())
	state.Enabled, state.StartAtBoot, state.ChangedBy, state.UpdatedAt = true, p.StartAtBoot, "api", time.Now().Unix()
	state.Policy = p.Persistent().Normalize()
	if err := saveState(state); err != nil {
		return protection.Problem(sysnet.ProblemState, "Cannot save the protection state: "+err.Error(), "Nothing was changed")
	}
	b.lastErr = b.apply(p)
	return b.lastErr
}

func (b *Backend) Update(ctx context.Context, p protection.Policy) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, _, err := helper.LoadState(stateFile())
	if err != nil || !state.Enabled {
		return err
	}
	persistent := p.Persistent().Normalize()
	if persistent.Fingerprint() != state.Policy.Fingerprint() {
		state.Policy, state.UpdatedAt = persistent, time.Now().Unix()
		if err := saveState(state); err != nil {
			return protection.Problem(sysnet.ProblemState, "Cannot save the protection state: "+err.Error(), "")
		}
	}
	p.StartAtBoot = state.StartAtBoot
	b.lastErr = b.apply(p)
	return b.lastErr
}

// Disable saves the disabled state first, then removes the filters.
func (b *Backend) Disable(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, err := b.open()
	if err != nil {
		return err
	}
	state, _, _ := helper.LoadState(stateFile())
	state.Enabled, state.ChangedBy, state.UpdatedAt = false, "api", time.Now().Unix()
	if err := saveState(state); err != nil {
		return protection.Problem(sysnet.ProblemState, "Cannot save the disabled state, so protection was left on: "+err.Error(),
			"Try: yuhaiin protection disable --recovery (as administrator)")
	}
	b.applied, b.tunnels, b.own = "", nil, false
	return e.Remove()
}

// Inspection is what WFP holds for Yuhaiin.
type Inspection struct {
	Known   bool
	Filters []Filter // labels and families of loaded filters
	Persist bool     // the baseline survives a reboot
	Err     error
}

func (b *Backend) inspect() Inspection {
	e, err := b.open()
	if err != nil {
		return Inspection{Err: err}
	}
	rules, err := e.Ours()
	if err != nil {
		return Inspection{Err: err}
	}
	in := Inspection{Known: true}
	for _, r := range rules {
		f := Filter{Label: r.Description, V6: r.Layer == wf.LayerALEAuthConnectV6, Permit: r.Action == wf.ActionPermit, Persistent: r.Persistent}
		in.Filters = append(in.Filters, f)
		if f.Label == blockLabel && r.Persistent {
			in.Persist = true
		}
	}
	return in
}

func blocks(in Inspection) (v4, v6 bool) {
	for _, f := range in.Filters {
		if f.Label == blockLabel && !f.Permit {
			if f.V6 {
				v6 = true
			} else {
				v4 = true
			}
		}
	}
	return
}

func (b *Backend) Status(ctx context.Context) (sysnet.ProtectionStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, _, stateErr := helper.LoadState(stateFile())
	in := b.inspect()
	st := Describe(in, state, stateErr)
	st.UpdatedAt = b.updatedAt
	if state.Enabled && stateErr == nil && b.applied != "" && !st.Effective {
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemModified, Message: "Yuhaiin's filters were removed by another program; they are restored"})
		b.session++
		b.applied = ""
	} else if state.Enabled && stateErr == nil && b.applied == "" {
		b.session++ // nothing applied by this process yet
	}
	if st.Effective {
		for _, t := range b.tunnels {
			st.TunnelInterfaces = append(st.TunnelInterfaces, t.Name)
		}
		st.OwnTraffic.Allowed = b.own
	}
	st.OwnTraffic.Method, st.OwnTraffic.Group = "application", b.app
	if ifaces, err := iface.List(); err == nil {
		for _, i := range ifaces {
			if i.Up && i.Type != iface.TypeLoopback && !slices.ContainsFunc(b.tunnels, func(t Tunnel) bool { return t.Name == i.Name }) {
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
	st.CheckedAt = time.Now().Unix()
	return st, nil
}

func problemOf(err error) sysnet.ProtectionProblem {
	if p, ok := errors.AsType[*protection.ProblemError](err); ok {
		return p.Problem
	}
	return sysnet.ProtectionProblem{Code: sysnet.ProblemPolicySync, Message: err.Error()}
}

// Describe turns WFP's state and the saved state into a status. WFP keeps
// no per-filter packet counters, so Blocked is null.
func Describe(in Inspection, state helper.State, stateErr error) sysnet.ProtectionStatus {
	st := protection.UnsupportedStatus()
	st.Supported, st.Backend, st.BackendName, st.Mode = true, "wfp", "Windows Filtering Platform", sysnet.ProtectionModeStandard
	st.Desired = sysnet.ProtectionSettings{Enabled: state.Enabled, StartAtBoot: state.StartAtBoot}
	st.Filter.Name = "Yuhaiin sublayer " + windows.GUID(SublayerID).String()
	v4, v6 := blocks(in)
	loaded := v4 && v6
	if in.Known {
		on := true
		st.Filter.Enabled, st.Filter.Registered, st.Filter.Loaded = &on, &loaded, &loaded
		st.Filter.Persistent = &in.Persist
	}
	if in.Err != nil {
		st.Problems = append(st.Problems, problemOf(in.Err))
	}
	if loaded {
		st.PrivateNetworks = protection.PrefixStrings(state.Policy.PrivateNetworks, 1000)
		st.BypassNetworks = protection.PrefixStrings(state.Policy.BypassNetworks, 500)
		st.BypassCount = len(state.Policy.BypassNetworks)
	}
	st.Effective = loaded
	switch {
	case stateErr != nil:
		st.State, st.Error = sysnet.ProtectionError, stateErr.Error()
	case !state.Enabled && !v4 && !v6:
		st.State = sysnet.ProtectionDisabled
	case !state.Enabled:
		st.State = sysnet.ProtectionError
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemModified, Message: "Protection is disabled but its filters are still loaded",
			Hint: "Run as administrator: yuhaiin protection disable --recovery"})
	case !loaded:
		st.State = sysnet.ProtectionError
	default:
		st.State = sysnet.ProtectionProtected
	}
	if state.Enabled && state.StartAtBoot && loaded && !in.Persist {
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemBootstrap, Message: "The block filters are not persistent; protection returns at startup only when Yuhaiin starts"})
	}
	return st
}

// Rules is the read-only rules view: every sublayer by weight (Yuhaiin's
// marked) and Yuhaiin's filters.
func (b *Backend) Rules(ctx context.Context) sysnet.ProtectionRules {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := sysnet.ProtectionRules{Backend: "wfp", ReadAt: time.Now().Unix(), Rulesets: []sysnet.ProtectionRuleset{}, Main: []sysnet.ProtectionMainRule{}}
	e, err := b.open()
	if err != nil {
		out.Reason = err.Error()
		return out
	}
	if subs, err := e.Sublayers(); err == nil {
		sort.SliceStable(subs, func(i, j int) bool { return subs[i].Weight > subs[j].Weight })
		for _, s := range subs {
			out.Main = append(out.Main, sysnet.ProtectionMainRule{Kind: "sublayer", Text: fmt.Sprintf("weight %d: %s", s.Weight, s.Name), Yuhaiin: s.ID == SublayerID})
		}
	} else {
		out.Errors = append(out.Errors, err.Error())
	}
	set := sysnet.ProtectionRuleset{Name: "Yuhaiin provider", Purpose: "protection", Rules: []sysnet.ProtectionRule{}}
	rules, err := e.Ours()
	if err != nil {
		out.Errors = append(out.Errors, err.Error())
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Weight > rules[j].Weight })
	var raw []byte
	for _, r := range rules {
		set.Rules = append(set.Rules, sysnet.ProtectionRule{Text: fmt.Sprintf("%s [weight %d%s]", r.Name, r.Weight, map[bool]string{true: ", persistent"}[r.Persistent]),
			Label: r.Description, Category: Category(r.Description)})
		raw = fmt.Appendf(raw, "%s %s weight=%d persistent=%v\n", r.ID, r.Name, r.Weight, r.Persistent)
		for _, c := range r.Conditions {
			raw = fmt.Appendf(raw, "    %s\n", c)
		}
	}
	out.Rulesets = append(out.Rulesets, set)
	out.Config = sysnet.ProtectionConfigFile{Path: "Base Filtering Engine (persistent filters)", Lines: []sysnet.ProtectionConfigLine{}}
	for _, r := range rules {
		if r.Persistent && r.Description == blockLabel {
			out.Config.Registered = true
		}
	}
	out.Raw = string(raw)
	out.Available = err == nil
	return out
}

// Recover removes Network Protection without the Yuhaiin core: it saves the
// disabled state first, then deletes Yuhaiin's filters, sublayer and
// provider, and checks both again.
func Recover(ctx context.Context) helper.RecoveryReport {
	var report helper.RecoveryReport
	step := func(name string, err error, detail string) bool {
		s := helper.RecoveryStep{Name: name, OK: err == nil, Detail: detail}
		if err != nil {
			s.Detail = err.Error()
		}
		report.Steps = append(report.Steps, s)
		return err == nil
	}
	if !Elevated() {
		step("administrator rights", errors.New("emergency recovery needs administrator rights; run it from an elevated terminal"), "")
		return report
	}
	step("administrator rights", nil, "elevated")
	e, err := Open()
	if err != nil {
		step("open the Windows Filtering Platform", err, "")
		return report
	}
	defer e.Close()
	state, exists, loadErr := helper.LoadState(stateFile())
	rules, _ := e.Ours()
	if !exists && len(rules) == 0 {
		step("Yuhaiin protection present", nil, "no saved state and no Yuhaiin filters; nothing to remove")
		report.Success = true
		return report
	}
	step("Yuhaiin protection present", nil, fmt.Sprintf("saved state: %v, filters: %d", exists, len(rules)))
	if loadErr != nil {
		_ = os.Rename(stateFile(), stateFile()+".damaged")
		state = helper.State{}
	}
	ok := true
	state.Enabled, state.ChangedBy, state.UpdatedAt = false, "recovery", time.Now().Unix()
	ok = step("save disabled state", saveState(state), "protection will not be restored when Yuhaiin starts") && ok
	ok = step("remove protection filters", e.Remove(), "only the Yuhaiin provider's filters, sublayer and provider were deleted") && ok
	left, err := e.Ours()
	if err == nil && len(left) != 0 {
		err = fmt.Errorf("%d Yuhaiin filters are still loaded", len(left))
	}
	ok = step("verify protection filters removed", err, "") && ok
	saved, _, err := helper.LoadState(stateFile())
	if err == nil && saved.Enabled {
		err = errors.New("the saved state still requests protection")
	}
	ok = step("verify disabled at next startup", err, "") && ok
	report.Success = ok
	return report
}
