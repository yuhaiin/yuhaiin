package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
)

const protectionSupported = true

const protectionPlatformHelp = `
  sudo yuhaiin protection restart
      Restart the protection service so it runs the installed binary (done
      automatically when Yuhaiin starts after an update). Protection stays
      in force while it restarts.
`

func protectionAdmin() bool                { return os.Geteuid() == 0 }
func protectionAdminCmd(cmd string) string { return "sudo yuhaiin protection " + cmd }
func protectionPlatformRecover(ctx context.Context) helper.RecoveryReport {
	return helper.NewRecovery().Run(ctx)
}

func protectionPlatformCommand(name string, args []string, stdout, stderr io.Writer) (int, bool) {
	switch name {
	case "restart":
		return protectionRestart(stdout, stderr), true
	case "daemon":
		// Run by launchd (io.github.yuhaiin.protection).
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := helper.RunDaemon(ctx); err != nil {
			fmt.Fprintln(stderr, "network protection service:", err)
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func protectionPlatformStatus(ctx context.Context) (sysnet.ProtectionStatus, string, string) {
	client := helper.NewClient("cli")
	defer client.Close()
	status, err := client.Call(ctx, helper.OpStatus, nil)
	if err == nil {
		note := ""
		if status.ServiceVersion != helper.BuildID() {
			note = fmt.Sprintf("The protection service runs build %s; this command is %s.\nRestart it to use the installed binary: sudo yuhaiin protection restart", status.ServiceVersion, helper.BuildID())
		}
		return status, "Running (version " + status.ServiceVersion + ")", note
	}
	service := "Not reachable (" + err.Error() + ")"
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
	return status, service, ""
}

func protectionPlatformDisable(ctx context.Context, stdout, stderr io.Writer) int {
	client := helper.NewClient("cli")
	defer client.Close()
	status, err := client.Call(ctx, helper.OpDisable, nil)
	if err != nil {
		if code := protectionProblemCode(err); code == sysnet.ProblemServiceDown || code == sysnet.ProblemServiceMissing {
			// The service only runs while protection is on.
			if state, _, stateErr := helper.LoadState(helper.StateFile); stateErr == nil && !state.Enabled &&
				len(pf.ParseRules(ruleText(ctx))) == 0 {
				fmt.Fprintln(stdout, "Network Protection is already disabled.")
				return 0
			}
			fmt.Fprintf(stderr, "Unable to connect to Yuhaiin Privileged Helper.\n\nYuhaiin Core may be unavailable.\n\n")
			printRecoveryHint(stderr, nil)
			return 1
		}
		printRecoveryHint(stderr, err)
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

func protectionRestart(stdout, stderr io.Writer) int {
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

func protectionProblemCode(err error) string {
	if p, ok := errors.AsType[*protection.ProblemError](err); ok {
		return p.Problem.Code
	}
	return ""
}
