package app

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/backup"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func TestCalculateHash(t *testing.T) {
	t.Log(calculateHash(&backup.BackupContent{}, &config.BackupOption{}))
}
