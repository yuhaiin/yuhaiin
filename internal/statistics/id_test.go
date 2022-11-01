package statistics

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestIDGenerate(t *testing.T) {
	var idGenerater IDGenerator

	assert.Equal(t, int64(1), idGenerater.Generate())
	assert.Equal(t, int64(2), idGenerater.Generate())
	assert.Equal(t, int64(3), idGenerater.Generate())
}