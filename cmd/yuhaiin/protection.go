package main

import (
	"bufio"
	"context"
	json "encoding/json/v2"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"golang.org/x/term"
)

const protectionHelp = `Usage:
  yuhaiin protection status [-json]
      Show the Network Protection (kill switch) state: what is requested,
      what the operating system really enforces, and why.

  yuhaiin protection disable [-yes]            (administrator)
      Turn the kill switch off. The setting is saved first, so it stays off
      after a restart.

  yuhaiin protection disable -recovery [-yes]  (administrator)
      Emergency recovery when Yuhaiin does not start: saves the kill switch
      as disabled and removes only Yuhaiin's firewall rules. It does not
      need the Yuhaiin core, its web interface or its configuration, and it
      never changes other programs' firewall rules.
` + protectionPlatformHelp

// protectionCommand runs "yuhaiin protection ..." and returns the exit code.
// It depends only on the operating system (and on macOS the protection
// service): not on the Yuhaiin core, its API or configuration.
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
	case "help", "-h", "--help":
		fmt.Fprint(stdout, protectionHelp)
		return 0
	}
	if code, ok := protectionPlatformCommand(args[0], args[1:], stdout, stderr); ok {
		return code
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
	if !protectionSupported {
		fmt.Fprintf(stdout, "Yuhaiin Network Protection\n\nStatus: Unsupported\nNetwork Protection is not available on %s.\n", runtime.GOOS)
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, service, note := protectionPlatformStatus(ctx)
	if *asJSON {
		data, _ := json.Marshal(status, json.Deterministic(true))
		fmt.Fprintln(stdout, string(data))
		return 0
	}
	printProtection(stdout, status, service)
	if note != "" {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, note)
	}
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
	fmt.Fprintf(w, "Backend: %s\n", onOff(s.BackendName != "", s.BackendName, "-"))
	fmt.Fprintf(w, "Rule Set: %s\n", onOff(s.Filter.Name != "", s.Filter.Name, "-"))
	fmt.Fprintf(w, "Firewall: %s\n", known(s.Filter.Enabled, "Enabled", "Disabled"))
	fmt.Fprintf(w, "Rules Evaluated by the System: %s\n", known(s.Filter.Registered, "Yes", "No"))
	fmt.Fprintf(w, "Rules Loaded: %s\n", known(s.Filter.Loaded, "Yes", "No"))
	if s.Filter.Persistent != nil {
		fmt.Fprintf(w, "Restored at Startup: %s\n", known(s.Filter.Persistent, "Yes", "No"))
	}
	if s.Filter.Reference != nil {
		fmt.Fprintf(w, "Enable Reference Held: %s\n", known(s.Filter.Reference, "Yes", "No"))
	}
	if service != "" {
		fmt.Fprintf(w, "Privileged Helper: %s\n", service)
	}
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
		how := s.OwnTraffic.Method
		if s.OwnTraffic.Group != "" {
			how += " " + s.OwnTraffic.Group
		}
		fmt.Fprintf(w, "Yuhaiin Traffic: %s\n", onOff(s.OwnTraffic.Allowed, "Allowed ("+how+")", "Blocked ("+reason+")"))
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
	recovery := fs.Bool("recovery", false, "emergency recovery without the Yuhaiin core or the protection service")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !protectionSupported {
		fmt.Fprintf(stdout, "Network Protection is not available on %s; nothing to disable.\n", runtime.GOOS)
		return 0
	}
	cmd := "disable"
	if *recovery {
		cmd += " --recovery"
	}
	if !protectionAdmin() {
		fmt.Fprintf(stderr, "Disabling Network Protection needs administrator rights.\n\nRun:\n\n  %s\n", protectionAdminCmd(cmd))
		return 1
	}
	if *recovery {
		if !*yes && !confirm(in, stdout, "Remove Yuhaiin's kill switch rules and keep protection off?") {
			fmt.Fprintln(stdout, "Cancelled.")
			return 1
		}
		report := protectionPlatformRecover(context.Background())
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
		fmt.Fprintln(stdout, "Other programs' firewall rules were not changed.")
		return 0
	}
	if !*yes && !confirm(in, stdout, "Disable the Yuhaiin kill switch?") {
		fmt.Fprintln(stdout, "Cancelled.")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return protectionPlatformDisable(ctx, stdout, stderr)
}

// printRecoveryHint is shown when a normal disable fails.
func printRecoveryHint(stderr io.Writer, err error) {
	if err != nil {
		fmt.Fprintf(stderr, "Disabling Network Protection failed: %v\n\n", err)
	}
	fmt.Fprintf(stderr, "You can try emergency recovery:\n\n  %s\n", protectionAdminCmd("disable --recovery"))
}
