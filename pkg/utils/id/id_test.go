package id

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestIDGenerate(t *testing.T) {
	var idGenerater IDGenerator

	assert.Equal(t, uint64(1), idGenerater.Generate())
	assert.Equal(t, uint64(2), idGenerater.Generate())
	assert.Equal(t, uint64(3), idGenerater.Generate())
}
