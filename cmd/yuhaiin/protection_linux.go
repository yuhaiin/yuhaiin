//go:build linux && !android

package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/nft"
)

const protectionSupported = true

const protectionPlatformHelp = `
  yuhaiin protection restore                   (run at boot by yuhaiin-protection.service)
      Load the saved protection rules before the network comes up.
`

func protectionAdmin() bool                                               { return os.Geteuid() == 0 }
func protectionAdminCmd(cmd string) string                                { return "sudo yuhaiin protection " + cmd }
func protectionPlatformRecover(ctx context.Context) helper.RecoveryReport { return nft.Recover(ctx) }

func protectionPlatformCommand(name string, _ []string, _, stderr io.Writer) (int, bool) {
	if name != "restore" {
		return 0, false
	}
	if err := nft.RestoreAtBoot(); err != nil {
		fmt.Fprintln(stderr, "restore network protection:", err)
		return 1, true
	}
	return 0, true
}

func protectionPlatformStatus(ctx context.Context) (sysnet.ProtectionStatus, string, string) {
	if os.Geteuid() != 0 {
		st := sysnet.ProtectionStatus{State: sysnet.ProtectionError, Supported: true, Backend: "nftables", BackendName: "Linux nftables"}
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Message: "nftables and the saved state can only be read as root", Hint: "Run: sudo yuhaiin protection status"})
		return st, "", ""
	}
	st, _ := nft.NewBackend(nil).Status(ctx)
	return st, "", "The rules are kept by the kernel; no separate service runs. " + nft.UnitName + " restores them at boot."
}

func protectionPlatformDisable(ctx context.Context, stdout, stderr io.Writer) int {
	b := nft.NewBackend(nil)
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
