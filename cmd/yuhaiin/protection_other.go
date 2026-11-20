//go:build !darwin && !windows && (!linux || android)

package main

import (
	"context"
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/helper"
)

const protectionSupported = false

const protectionPlatformHelp = ""

func protectionAdmin() bool                { return false }
func protectionAdminCmd(cmd string) string { return "yuhaiin protection " + cmd }
func protectionPlatformRecover(context.Context) helper.RecoveryReport {
	return helper.RecoveryReport{Success: true}
}
func protectionPlatformCommand(string, []string, io.Writer, io.Writer) (int, bool) { return 0, false }
func protectionPlatformStatus(context.Context) (sysnet.ProtectionStatus, string, string) {
	return sysnet.ProtectionStatus{State: sysnet.ProtectionUnsupported}, "", ""
}
func protectionPlatformDisable(context.Context, io.Writer, io.Writer) int { return 0 }
