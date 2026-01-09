package api

import (
	"github.com/Asutorufa/yuhaiin/pkg/structs/backup"
	"github.com/Asutorufa/yuhaiin/pkg/structs/config"
)

type Backup struct {
	Save    Service[config.BackupOption, struct{}]
	Get     Service[struct{}, config.BackupOption]
	Backup  Service[struct{}, struct{}]
	Restore Service[backup.RestoreOption, struct{}]
}
