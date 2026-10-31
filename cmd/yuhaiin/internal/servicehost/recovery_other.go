//go:build !linux

package servicehost

import backupapp "github.com/Asutorufa/yuhaiin/pkg/app/backup"

func NewRecoveryMaintainer(string) backupapp.RecoveryMaintainer { return nil }
