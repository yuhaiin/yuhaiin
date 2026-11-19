package helper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
)

// Recovery removes Network Protection without the service, the Yuhaiin core
// or its configuration. It only touches Yuhaiin's own state file, its
// protection anchor and its own PF reference; the packet filter itself, the
// main ruleset and other programs' anchors and references are left alone.
type Recovery struct {
	StateFile string
	Engine    *pf.Engine
	// StopService unloads the protection service so it cannot apply the
	// rules again while recovery runs.
	StopService func(context.Context) error
	BootID      func() string
	Euid        func() int
}

// NewRecovery returns the recovery for this system.
func NewRecovery() Recovery {
	return Recovery{StateFile: StateFile, Engine: pf.NewEngine(StateDir), StopService: StopDaemon, BootID: BootID, Euid: os.Geteuid}
}

// RecoveryStep is one step and its outcome.
type RecoveryStep struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitzero"`
	Detail  string `json:"detail,omitzero"`
}

// RecoveryReport lists every step. Success is set only when the operating
// system state was verified: no protection rules loaded and protection
// saved as disabled for the next start.
type RecoveryReport struct {
	Steps   []RecoveryStep `json:"steps"`
	Success bool           `json:"success"`
}

func (r *RecoveryReport) add(name string, err error, detail string) bool {
	step := RecoveryStep{Name: name, OK: err == nil, Detail: detail}
	if err != nil {
		step.Detail = err.Error()
	}
	r.Steps = append(r.Steps, step)
	return err == nil
}

func (r *RecoveryReport) skip(name, detail string) {
	r.Steps = append(r.Steps, RecoveryStep{Name: name, OK: true, Skipped: true, Detail: detail})
}

// ErrNotRoot is returned when recovery runs without administrator rights.
var ErrNotRoot = errors.New("emergency recovery needs administrator rights; run it with sudo")

// Run performs the recovery in a fixed order: the disabled state is saved
// (and synced) before any rule is removed, so neither the service nor a
// restart can apply protection again; then the service is stopped, the
// rules removed, Yuhaiin's reference released, and both the rules and the
// saved state are checked again.
func (rc Recovery) Run(ctx context.Context) RecoveryReport {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var report RecoveryReport
	ok := true
	if rc.Euid() != 0 {
		report.add("administrator rights", ErrNotRoot, "")
		return report
	}
	report.add("administrator rights", nil, "running as root")

	state, exists, loadErr := LoadState(rc.StateFile)
	in := rc.Engine.Inspect(ctx)
	loaded := pf.LoadedID(in.Rules) != "" || (in.RulesKnown && len(in.Rules) > 0)
	if !exists && !loaded && !in.Conf.Managed {
		report.add("Yuhaiin protection present", nil, "no saved state and no protection rules; nothing to remove")
		report.Success = true
		return report
	}
	report.add("Yuhaiin protection present", nil, fmt.Sprintf("saved state: %v, rules loaded: %v", exists, loaded))

	if errors.Is(loadErr, ErrCorrupt) {
		quarantine(rc.StateFile)
		state = State{}
	} else if loadErr != nil {
		state = State{}
	}
	next := state
	next.Enabled, next.ChangedBy, next.UpdatedAt = false, "recovery", time.Now().Unix()
	if err := SaveState(rc.StateFile, next); !report.add("save disabled state", err, "protection will not be restored at the next startup") {
		ok = false
	}

	if rc.StopService != nil {
		if !report.add("stop protection service", rc.StopService(ctx), "it starts again at the next boot and keeps protection off") {
			ok = false
		}
	}

	if !report.add("remove protection rules", rc.Engine.Flush(ctx), "only the "+rc.Engine.Anchor+" anchor was flushed") {
		ok = false
	}

	if state.Token != "" && rc.BootID != nil && state.TokenBoot == rc.BootID() {
		err := rc.Engine.Release(ctx, state.Token)
		report.add("release Yuhaiin's packet filter reference", err, "other programs' references are kept")
		// A failed release only means the reference was already gone.
	} else {
		report.skip("release Yuhaiin's packet filter reference", "Yuhaiin holds no reference in this boot session")
	}
	if next.Token != "" {
		next.Token, next.TokenBoot = "", ""
		if err := SaveState(rc.StateFile, next); err != nil {
			report.add("save disabled state", err, "")
			ok = false
		}
	}

	after := rc.Engine.Inspect(ctx)
	var verifyErr error
	switch {
	case !after.RulesKnown:
		verifyErr = errors.Join(append([]error{errors.New("cannot read the protection anchor")}, after.Errors...)...)
	case len(after.Rules) != 0:
		verifyErr = fmt.Errorf("%d protection rules are still loaded", len(after.Rules))
	}
	if !report.add("verify protection rules removed", verifyErr, "") {
		ok = false
	}
	saved, _, err := LoadState(rc.StateFile)
	if err == nil && saved.Enabled {
		err = errors.New("the saved state still requests protection")
	}
	if !report.add("verify disabled at next startup", err, "") {
		ok = false
	}
	report.Success = ok
	return report
}
