package system

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestNM(t *testing.T) {
	m, err := newNMManager("")
	assert.NoError(t, err)

	t.Log(m.GetBaseConfig())
}
