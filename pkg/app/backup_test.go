package app

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func TestCalculateBytesHash(t *testing.T) {
	t.Log(calculateBytesHash([]byte("state"), &config.S3{}))
}
