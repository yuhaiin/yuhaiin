package pf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
)

// Engine runs pfctl for one anchor. It only ever touches Yuhaiin's anchors,
// its managed pf.conf lines and its own enable reference: it never runs
// "pfctl -d", never flushes the main ruleset or other anchors, and never
// kills states.
type Engine struct {
	// Pfctl is the pfctl executable, Conf the main ruleset file and
	// BackupDir where the previous pf.conf is kept.
	Pfctl, Conf, BackupDir string
	// Anchor is the anchor rules are loaded into.
	Anchor string
	// Run executes a fixed executable without a shell; tests replace it.
	Run func(ctx context.Context, stdin, name string, args ...string) (string, error)
}

// BackupDir is where the previous pf.conf and the edit lock are kept.
const BackupDir = "/Library/Application Support/io.github.yuhaiin/protection"

// NewEngine returns the engine for the kill switch anchor on this system.
func NewEngine(backupDir string) *Engine {
	return &Engine{Pfctl: "/sbin/pfctl", Conf: "/etc/pf.conf", BackupDir: backupDir, Anchor: ProtectionAnchor, Run: Exec}
}

// Exec runs name with args (no shell) and returns combined output.
func Exec(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.String(), &CommandError{Args: append([]string{filepath.Base(name)}, args...), Output: strings.TrimSpace(out.String()), Err: err}
	}
	return out.String(), nil
}

// CommandError is a failed pfctl call with its output.
type CommandError struct {
	Args   []string
	Output string
	Err    error
}

func (e *CommandError) Error() string {
	msg := strings.Join(e.Args, " ") + ": " + e.Err.Error()
	if e.Output != "" {
		msg += ": " + lastLines(e.Output, 6)
	}
	return msg
}

func (e *CommandError) Unwrap() error { return e.Err }

func lastLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " / ")
}

func (e *Engine) pfctl(ctx context.Context, stdin string, args ...string) (string, error) {
	out, err := e.Run(ctx, stdin, e.Pfctl, args...)
	if err != nil && (errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)) {
		return out, protection.Problem(sysnet.ProblemEnableFailed, "pfctl was not found at "+e.Pfctl, "Network Protection needs the macOS packet filter")
	}
	return out, err
}

// Inspection is the operating system state relevant to the kill switch.
type Inspection struct {
	// EnabledKnown is false when "pfctl -s info" could not be read.
	Enabled, EnabledKnown bool
	Tokens                []string
	// FilterRef and NATRef: the running main ruleset evaluates the anchors.
	FilterRef, NATRef, RefKnown bool
	// Conf is the registration found in pf.conf.
	Conf      ConfRegistration
	ConfKnown bool
	// Rules are the rules loaded into the anchor.
	Rules      []RuleCounters
	RulesKnown bool
	Errors     []error
}

// Inspect reads the current state. Failures are collected, not fatal, so
// status can show what is known.
func (e *Engine) Inspect(ctx context.Context) Inspection {
	var in Inspection
	if out, err := e.pfctl(ctx, "", "-s", "info"); err != nil {
		in.Errors = append(in.Errors, err)
	} else {
		in.Enabled, in.EnabledKnown = ParseEnabled(out)
	}
	if out, err := e.pfctl(ctx, "", "-s", "References"); err == nil {
		in.Tokens = ParseReferences(out)
	}
	rules, err1 := e.pfctl(ctx, "", "-s", "rules")
	nat, err2 := e.pfctl(ctx, "", "-s", "nat")
	if err1 != nil || err2 != nil {
		in.Errors = append(in.Errors, errors.Join(err1, err2))
	} else {
		in.FilterRef, in.NATRef, in.RefKnown = MainReferences(rules, "anchor"), MainReferences(nat, "nat-anchor"), true
	}
	if data, err := os.ReadFile(e.Conf); err != nil {
		in.Errors = append(in.Errors, err)
	} else {
		in.Conf, in.ConfKnown = Registered(string(data)), true
	}
	if out, err := e.pfctl(ctx, "", "-a", e.Anchor, "-v", "-s", "rules"); err != nil {
		in.Errors = append(in.Errors, err)
	} else {
		in.Rules, in.RulesKnown = ParseRules(out), true
	}
	return in
}

// Load validates rules and then replaces the anchor's rules and tables in
// one transaction. A rejected ruleset leaves the loaded one in force.
func (e *Engine) Load(ctx context.Context, rs Ruleset) error {
	if _, err := e.pfctl(ctx, rs.Text, "-n", "-a", e.Anchor, "-f", "-"); err != nil {
		if _, ok := errors.AsType[*protection.ProblemError](err); ok {
			return err
		}
		return protection.Problem(sysnet.ProblemRulesRejected, "The packet filter rejected the protection rules: "+err.Error(), "The previous rules stay in force; report this as a bug")
	}
	if _, err := e.pfctl(ctx, rs.Text, "-a", e.Anchor, "-f", "-"); err != nil {
		return fmt.Errorf("load protection rules: %w", err)
	}
	return nil
}

// Flush removes the rules and tables of the anchor only.
func (e *Engine) Flush(ctx context.Context) error {
	_, err1 := e.pfctl(ctx, "", "-a", e.Anchor, "-F", "rules")
	_, err2 := e.pfctl(ctx, "", "-a", e.Anchor, "-F", "Tables")
	return errors.Join(err1, err2)
}

// Acquire takes an enable reference ("pfctl -E") and returns its token.
func (e *Engine) Acquire(ctx context.Context) (string, error) {
	out, err := e.pfctl(ctx, "", "-E")
	if err != nil {
		return "", protection.Problem(sysnet.ProblemEnableFailed, "The packet filter could not be enabled: "+err.Error(), "")
	}
	token := ParseToken(out)
	if token == "" {
		return "", protection.Problem(sysnet.ProblemEnableFailed, "pfctl -E did not return a reference token", "")
	}
	return token, nil
}

// Release drops a reference Yuhaiin took. The packet filter stays enabled
// while other programs hold references.
func (e *Engine) Release(ctx context.Context, token string) error {
	if !numberOnly.MatchString(token) {
		return fmt.Errorf("invalid reference token %q", token)
	}
	_, err := e.pfctl(ctx, "", "-X", token)
	return err
}

// ReloadMain loads the main ruleset from pf.conf.
func (e *Engine) ReloadMain(ctx context.Context) error {
	_, err := e.pfctl(ctx, "", "-f", e.Conf)
	return err
}

func (e *Engine) validateConf(ctx context.Context, path string) error {
	_, err := e.pfctl(ctx, "", "-n", "-f", path)
	return err
}

// EnsureRegistered makes the main ruleset evaluate Yuhaiin's anchors, now
// and after a restart:
//
//  1. pf.conf is checked; if it lacks the lines, the current file must
//     parse, the edited copy must parse, the original is backed up and the
//     file is replaced atomically;
//  2. if the running main ruleset lacks the reference, it is reloaded from
//     pf.conf; if that fails, the original pf.conf is restored and reloaded.
//
// withNAT asks for the nat-anchor too (forwarding needs it, the kill switch
// does not). If a customized pf.conf rejects it, only the filter anchor is
// registered.
func (e *Engine) EnsureRegistered(ctx context.Context, withNAT bool) (changed bool, err error) {
	unlock, err := lockConf(e.BackupDir)
	if err != nil {
		return false, protection.Problem(sysnet.ProblemRegistration, "Cannot lock "+e.Conf+" for editing: "+err.Error(), "")
	}
	defer unlock()
	data, err := os.ReadFile(e.Conf)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, protection.Problem(sysnet.ProblemRegistration, "Cannot read "+e.Conf+": "+err.Error(), "")
	}
	original := string(data)
	reg := Registered(original)
	if !reg.Filter || (withNAT && !reg.NAT) {
		if original != "" {
			if err := e.validateConf(ctx, e.Conf); err != nil {
				return false, protection.Problem(sysnet.ProblemRegistration, "The existing "+e.Conf+" does not load: "+err.Error(), "Fix "+e.Conf+" (pfctl -nf "+e.Conf+") and enable protection again; Yuhaiin does not edit a file that is already broken")
			}
		}
		candidate, _ := Register(original, withNAT)
		if err := e.checkCandidate(ctx, candidate); err != nil && withNAT {
			candidate, _ = Register(original, false)
			err = e.checkCandidate(ctx, candidate)
			if err != nil {
				return false, err
			}
		} else if err != nil {
			return false, err
		}
		if err := e.backup(original); err != nil {
			return false, err
		}
		if err := WriteFileAtomic(e.Conf, []byte(candidate), confMode(e.Conf)); err != nil {
			return false, protection.Problem(sysnet.ProblemRegistration, "Cannot write "+e.Conf+": "+err.Error(), "")
		}
		changed = true
	}
	in := e.Inspect(ctx)
	if in.RefKnown && in.FilterRef && (!withNAT || in.NATRef || !Registered(e.readConf()).NAT) {
		return changed, nil
	}
	if err := e.ReloadMain(ctx); err != nil {
		if changed {
			// Put back what was there and load it again.
			restoreErr := WriteFileAtomic(e.Conf, []byte(original), confMode(e.Conf))
			if restoreErr == nil && original != "" {
				restoreErr = e.ReloadMain(ctx)
			}
			if restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("restore %s: %w", e.Conf, restoreErr))
			}
		}
		return false, protection.Problem(sysnet.ProblemRegistration, "Loading "+e.Conf+" failed: "+err.Error(), "The previous "+e.Conf+" was restored")
	}
	after := e.Inspect(ctx)
	if !after.FilterRef {
		return changed, protection.Problem(sysnet.ProblemRegistration, "The packet filter main ruleset does not evaluate the "+Anchor+" anchor after loading "+e.Conf, "Check "+e.Conf+" for include files or rules that replace the main ruleset")
	}
	return changed, nil
}

func (e *Engine) readConf() string {
	data, _ := os.ReadFile(e.Conf)
	return string(data)
}

func (e *Engine) checkCandidate(ctx context.Context, candidate string) error {
	dir := e.BackupDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".pf.conf.check-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(candidate); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := e.validateConf(ctx, tmp.Name()); err != nil {
		return protection.Problem(sysnet.ProblemRegistration, "The edited "+e.Conf+" would not load: "+err.Error(), e.Conf+" was not changed")
	}
	return nil
}

// backup keeps the last pf.conf before Yuhaiin changed it.
func (e *Engine) backup(original string) error {
	if err := os.MkdirAll(e.BackupDir, 0o700); err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(e.BackupDir, "pf.conf.previous"), []byte(original), 0o600)
}

// Unregister removes the managed lines from pf.conf and reloads the main
// ruleset if it still evaluates them. Lines Yuhaiin did not add are kept.
func (e *Engine) Unregister(ctx context.Context) (bool, error) {
	unlock, err := lockConf(e.BackupDir)
	if err != nil {
		return false, err
	}
	defer unlock()
	data, err := os.ReadFile(e.Conf)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	original := string(data)
	updated, changed := Unregister(original)
	if !changed {
		return false, nil
	}
	if err := e.checkCandidate(ctx, updated); err != nil {
		return false, err
	}
	if err := e.backup(original); err != nil {
		return false, err
	}
	if err := WriteFileAtomic(e.Conf, []byte(updated), confMode(e.Conf)); err != nil {
		return false, err
	}
	in := e.Inspect(ctx)
	if in.FilterRef || in.NATRef {
		if err := e.ReloadMain(ctx); err != nil {
			return true, fmt.Errorf("reload %s: %w", e.Conf, err)
		}
	}
	return true, nil
}

func confMode(path string) fs.FileMode {
	if info, err := os.Stat(path); err == nil {
		return info.Mode().Perm()
	}
	return 0o644
}

// WriteFileAtomic replaces path with data: a temporary file in the same
// directory is written and synced, renamed over path, and the directory is
// synced, so a crash leaves either the old or the new content.
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if name != "" {
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	name = ""
	if d, err := os.Open(dir); err == nil {
		err = d.Sync()
		d.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
