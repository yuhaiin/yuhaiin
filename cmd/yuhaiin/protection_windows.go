//go:build windows

package main

import (
	"context"
	"fmt"
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/wfp"
)

const protectionSupported = true

const protectionPlatformHelp = `
  Run the commands that change protection from an elevated terminal
  (Run as administrator).
`

func protectionAdmin() bool { return wfp.Elevated() }
func protectionAdminCmd(cmd string) string {
	return "yuhaiin protection " + cmd + "   (in a terminal opened with Run as administrator)"
}
func protectionPlatformRecover(ctx context.Context) helper.RecoveryReport { return wfp.Recover(ctx) }

func protectionPlatformCommand(string, []string, io.Writer, io.Writer) (int, bool) { return 0, false }

func protectionPlatformStatus(ctx context.Context) (sysnet.ProtectionStatus, string, string) {
	b := wfp.NewBackend()
	defer b.Close()
	st, _ := b.Status(ctx)
	return st, "", "The filters are kept by the Windows Filtering Platform; no separate service runs."
}

func protectionPlatformDisable(ctx context.Context, stdout, stderr io.Writer) int {
	b := wfp.NewBackend()
	defer b.Close()
	if err := b.Disable(ctx); err != nil {
		printRecoveryHint(stderr, err)
		return 1
	}
	st, _ := b.Status(ctx)
	if st.Effective || st.Desired.Enabled {
		printProtection(stdout, st, "")
		printRecoveryHint(stderr, nil)
		return 1
	}
	fmt.Fprintln(stdout, "Network Protection is disabled and will stay disabled after a restart.")
	return 0
}
