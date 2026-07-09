package app

import (
	"testing"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
)

func TestCalculateBytesHash(t *testing.T) {
	t.Log(calculateBytesHash([]byte("state"), contractbackup.S3{}))
}
