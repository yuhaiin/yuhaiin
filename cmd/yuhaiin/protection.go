package main

import (
	"bufio"
	"context"
	json "encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
	"golang.org/x/term"
)

const protectionHelp = `Usage:
  yuhaiin protection status [-json]
      Show the Network Protection (kill switch) state: what is requested,
      what the operating system really enforces, and why.

  sudo yuhaiin protection disable [-yes]
      Turn the kill switch off through the protection service. The setting
      is saved first, so it stays off after a restart.

  sudo yuhaiin protection restart
      Restart the protection service so it runs the installed binary (done
      automatically when Yuhaiin starts after an update). Protection stays
      in force while it restarts.

  sudo yuhaiin protection disable -recovery [-yes]
      Emergency recovery when Yuhaiin or the protection service does not
      start: saves the kill switch as disabled, stops the protection
      service and removes only Yuhaiin's packet filter rules. It does not
      need the Yuhaiin core, its web interface or its configuration, and it
      never turns the packet filter off for other programs.
`

// protectionCommand runs "yuhaiin protection ..." and returns the exit code.
// It depends only on the protection service or, with -recovery, on nothing
// but the packet filter: not on the Yuhaiin core, its API or configuration.
func protectionCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, protectionHelp)
		return 2
	}
	switch args[0] {
	case "status":
		return protectionStatus(args[1:], stdout, stderr)
	case "disable":
		return protectionDisable(args[1:], os.Stdin, stdout, stderr)
	case "restart":
		return protectionRestart(stdout, stderr)
	case "daemon":
		// Run by launchd (io.github.yuhaiin.protection).
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := helper.RunDaemon(ctx); err != nil {
			fmt.Fprintln(stderr, "network protection service:", err)
			return 1
		}
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, protectionHelp)
		return 0
	}
	fmt.Fprintf(stderr, "unknown protection command %q\n\n%s", args[0], protectionHelp)
	return 2
}

func protectionStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("protection status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print the status as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !helper.Supported {
		fmt.Fprintf(stdout, "Yuhaiin Network Protection\n\nStatus: Unsupported\nNetwork Protection is not available on %s.\n", runtime.GOOS)
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := helper.NewClient("cli")
	defer client.Close()
	status, err := client.Call(ctx, helper.OpStatus, nil)
	service := "Running"
	if err != nil {
		service = "Not reachable (" + err.Error() + ")"
		stopped := "Not running (it runs only while the kill switch is on)"
		if os.Geteuid() == 0 {
			// Read the packet filter and saved state directly.
			state, _, stateErr := helper.LoadState(helper.StateFile)
			status = helper.Describe(pf.NewEngine(helper.StateDir).Inspect(ctx), state, stateErr)
			if stateErr == nil && !state.Enabled {
				service = stopped
			}
		} else if helper.DaemonDisabled(ctx) && !helper.DaemonLoaded(ctx) {
			status = sysnet.ProtectionStatus{State: sysnet.ProtectionDisabled, Supported: true}
			service = stopped
			status.Problems = append(status.Problems, sysnet.ProtectionProblem{Message: "The packet filter was not read", Hint: "To verify it, run: sudo yuhaiin protection status"})
		} else {
			status = sysnet.ProtectionStatus{State: sysnet.ProtectionError, Supported: true}
			status.Problems = append(status.Problems, sysnet.ProtectionProblem{Message: "The packet filter state cannot be read without the service", Hint: "Run: sudo yuhaiin protection status"})
		}
	}
	if *asJSON {
		data, _ := json.Marshal(status, json.Deterministic(true))
		fmt.Fprintln(stdout, string(data))
		return 0
	}
	if err == nil {
		service += " (version " + status.ServiceVersion + ")"
	}
	printProtection(stdout, status, service)
	if err == nil && status.ServiceVersion != helper.BuildID() {
		fmt.Fprintf(stdout, "\nThe protection service runs build %s; this command is %s.\nRestart it to use the installed binary: sudo yuhaiin protection restart\n", status.ServiceVersion, helper.BuildID())
	}
	return 0
}

func protectionRestart(stdout, stderr io.Writer) int {
	if !helper.Supported {
		fmt.Fprintf(stdout, "Network Protection is not available on %s.\n", runtime.GOOS)
		return 0
	}
	if os.Geteuid() != 0 {
		fmt.Fprintf(stderr, "Restarting the protection service needs administrator rights.\n\nRun:\n\n  sudo yuhaiin protection restart\n")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	before := ""
	c := helper.NewClient("cli")
	if st, err := c.Call(ctx, helper.OpStatus, nil); err == nil {
		before = st.ServiceVersion
	}
	c.Close()
	if err := helper.RestartDaemon(ctx); err != nil {
		fmt.Fprintf(stderr, "Restarting the protection service failed: %v\n\nProtection rules stay in force. To remove them without the service:\n\n  sudo yuhaiin protection disable --recovery\n", err)
		return 1
	}
	c = helper.NewClient("cli")
	defer c.Close()
	st, err := c.Call(ctx, helper.OpStatus, nil)
	if err != nil {
		fmt.Fprintf(stderr, "The protection service did not answer after restarting: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Protection service restarted: %s -> %s\nStatus: %s\n", onOff(before != "", before, "-"), st.ServiceVersion, stateNames[st.State])
	return 0
}

func onOff(v bool, on, off string) string {
	if v {
		return on
	}
	return off
}

func known(v *bool, yes, no string) string {
	if v == nil {
		return "Unknown"
	}
	return onOff(*v, yes, no)
}

var stateNames = map[string]string{
	sysnet.ProtectionUnsupported: "Unsupported", sysnet.ProtectionDisabled: "Disabled", sysnet.ProtectionInitializing: "Initializing",
	sysnet.ProtectionProtected: "Protected", sysnet.ProtectionUpdating: "Updating", sysnet.ProtectionDegraded: "Degraded", sysnet.ProtectionError: "Error",
}

func printProtection(w io.Writer, s sysnet.ProtectionStatus, service string) {
	fmt.Fprintln(w, "Yuhaiin Network Protection")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Status: %s\n\n", stateNames[s.State])
	fmt.Fprintf(w, "Desired State: %s\n", onOff(s.Desired.Enabled, "Enabled", "Disabled"))
	fmt.Fprintf(w, "Effective State: %s\n", onOff(s.Effective, "Protected", "Not Protected"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Backend: macOS PF\n")
	fmt.Fprintf(w, "Anchor: %s\n", pf.ProtectionAnchor)
	fmt.Fprintf(w, "PF: %s\n", known(s.Filter.Enabled, "Enabled", "Disabled"))
	fmt.Fprintf(w, "Anchor Registered: %s (pf.conf: %s)\n", known(s.Filter.Registered, "Yes", "No"), known(s.Filter.Persistent, "yes", "no"))
	fmt.Fprintf(w, "Rules Loaded: %s\n", known(s.Filter.Loaded, "Yes", "No"))
	fmt.Fprintf(w, "PF Reference Held: %s\n", known(s.Filter.Reference, "Yes", "No"))
	fmt.Fprintf(w, "Privileged Helper: %s\n", service)
	fmt.Fprintf(w, "Boot Persistence: %s\n", onOff(s.Desired.Enabled && s.Desired.StartAtBoot, "Enabled", "Disabled"))
	if s.UpdatedAt != 0 {
		fmt.Fprintf(w, "Last Successful Sync: %s\n", time.Unix(s.UpdatedAt, 0).Format(time.RFC3339))
	} else {
		fmt.Fprintf(w, "Last Successful Sync: -\n")
	}
	fmt.Fprintf(w, "Last Error: %s\n", onOff(s.Error != "", s.Error, "-"))
	if s.Effective {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Tunnel Interfaces: %s\n", list(s.TunnelInterfaces))
		fmt.Fprintf(w, "Protected Interfaces: %s\n", list(s.PhysicalInterfaces))
		fmt.Fprintf(w, "Private Networks: %d\n", len(s.PrivateNetworks))
		fmt.Fprintf(w, "Bypass Networks: %d\n", s.BypassCount)
		reason := s.OwnTraffic.Reason
		if reason == "" {
			reason = "Yuhaiin is not connected"
		}
		fmt.Fprintf(w, "Yuhaiin Traffic: %s\n", onOff(s.OwnTraffic.Allowed, "Allowed (socket group "+s.OwnTraffic.Group+")", "Blocked ("+reason+")"))
		if s.Blocked != nil {
			fmt.Fprintf(w, "Blocked Packets: %d (%d bytes)\n", s.Blocked.Packets, s.Blocked.Bytes)
		}
	}
	if len(s.Problems) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Reason:")
		for _, p := range s.Problems {
			fmt.Fprintf(w, "  - %s\n", p.Message)
			if p.Hint != "" {
				fmt.Fprintf(w, "    %s\n", p.Hint)
			}
		}
	}
}

func list(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return strings.Join(v, ", ")
}

func confirm(in io.Reader, out io.Writer, question string) bool {
	if f, ok := in.(*os.File); ok && !term.IsTerminal(int(f.Fd())) {
		fmt.Fprintln(out, question+" [y/N]: no terminal; pass -yes to confirm")
		return false
	}
	fmt.Fprint(out, question+" [y/N] ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

func protectionDisable(args []string, in io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("protection disable", flag.ContinueOnError)
	fs.SetOutput(stderr)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	recovery := fs.Bool("recovery", false, "emergency recovery without the protection service")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !helper.Supported {
		fmt.Fprintf(stdout, "Network Protection is not available on %s; nothing to disable.\n", runtime.GOOS)
		return 0
	}
	if os.Geteuid() != 0 {
		cmd := "sudo yuhaiin protection disable"
		if *recovery {
			cmd += " --recovery"
		}
		fmt.Fprintf(stderr, "Disabling Network Protection needs administrator rights.\n\nRun:\n\n  %s\n", cmd)
		return 1
	}
	if *recovery {
		if !*yes && !confirm(in, stdout, "Remove Yuhaiin's kill switch rules and keep protection off?") {
			fmt.Fprintln(stdout, "Cancelled.")
			return 1
		}
		report := helper.NewRecovery().Run(context.Background())
		fmt.Fprintln(stdout, "Yuhaiin Network Protection emergency recovery")
		fmt.Fprintln(stdout)
		for _, step := range report.Steps {
			mark := "OK  "
			switch {
			case step.Skipped:
				mark = "SKIP"
			case !step.OK:
				mark = "FAIL"
			}
			fmt.Fprintf(stdout, "[%s] %s", mark, step.Name)
			if step.Detail != "" {
				fmt.Fprintf(stdout, ": %s", step.Detail)
			}
			fmt.Fprintln(stdout)
		}
		fmt.Fprintln(stdout)
		if !report.Success {
			fmt.Fprintln(stdout, "Recovery did NOT complete; see the failed steps above. Network Protection may still be active or may return at the next startup.")
			return 1
		}
		fmt.Fprintln(stdout, "Network Protection is disabled and will stay disabled after a restart.")
		fmt.Fprintln(stdout, "Other programs' packet filter rules and references were not changed.")
		return 0
	}
	if !*yes && !confirm(in, stdout, "Disable the Yuhaiin kill switch?") {
		fmt.Fprintln(stdout, "Cancelled.")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client := helper.NewClient("cli")
	defer client.Close()
	status, err := client.Call(ctx, helper.OpDisable, nil)
	if err != nil {
		var problem *protection.ProblemError
		if errors.As(err, &problem) && (problem.Problem.Code == sysnet.ProblemServiceDown || problem.Problem.Code == sysnet.ProblemServiceMissing) {
			// The service only runs while protection is on.
			if state, _, stateErr := helper.LoadState(helper.StateFile); stateErr == nil && !state.Enabled &&
				len(pf.ParseRules(ruleText(ctx))) == 0 {
				fmt.Fprintln(stdout, "Network Protection is already disabled.")
				return 0
			}
			fmt.Fprintf(stderr, "Unable to connect to Yuhaiin Privileged Helper.\n\nYuhaiin Core may be unavailable.\n\nYou can try emergency recovery:\n\n  sudo yuhaiin protection disable --recovery\n")
			return 1
		}
		fmt.Fprintf(stderr, "Disabling Network Protection failed: %v\n\nYou can try emergency recovery:\n\n  sudo yuhaiin protection disable --recovery\n", err)
		return 1
	}
	if status.Desired.Enabled || status.Effective || (status.Filter.Loaded != nil && *status.Filter.Loaded) {
		printProtection(stdout, status, "Running")
		fmt.Fprintln(stderr, "\nThe protection service did not confirm that the rules are gone. Try: sudo yuhaiin protection disable --recovery")
		return 1
	}
	fmt.Fprintln(stdout, "Network Protection is disabled and will stay disabled after a restart.")
	return 0
}

// ruleText reads the protection anchor's rules directly.
func ruleText(ctx context.Context) string {
	e := pf.NewEngine(helper.StateDir)
	out, _ := e.Run(ctx, "", e.Pfctl, "-a", e.Anchor, "-s", "rules")
	return out
}
