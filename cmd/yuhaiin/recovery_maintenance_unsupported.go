//go:build !linux

package main

import (
	"errors"
	backupapp "github.com/Asutorufa/yuhaiin/pkg/app/backup"
)

func newRecoveryMaintainer(string) backupapp.RecoveryMaintainer { return nil }
func recoveryMaintenanceHelper([]string) error {
	return errors.New("installed-service recovery maintenance is unavailable on this platform; use the offline recovery CLI")
}
func recoveryMaintenanceRestartHelper(args []string) error {
	return recoveryMaintenanceHelper(args)
}
