package app

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/backup"
)

func TestCalculateHash(t *testing.T) {
	t.Log(calculateHash(&backup.BackupContent{}, &backup.BackupOption{}))
}
