package yuhaiin

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestStore(t *testing.T) {
	assert.NoError(t, InitDB(""))
	defer db.Close()
	GetStore("default").PutFloat("float", 3.1415926)
	t.Log(GetStore("default").GetFloat("float"))
	assert.Equal(t, float32(3.1415926), GetStore("default").GetFloat("float"))
}
