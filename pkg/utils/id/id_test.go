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

func TestUUID(t *testing.T) {
	u := GenerateUUID()

	t.Log(u.String())
	t.Log(u.Base32())
	t.Log(u.BigInt())

	t.Log(u.Bytes())
	x, err := ParseUUID(u.String())
	t.Log(x, err)

	x, err = ParseUUID(u.HexString())
	t.Log(x, err)
}
