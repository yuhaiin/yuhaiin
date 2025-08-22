package interfaces

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestGetRouter(t *testing.T) {
	r, err := routes()
	assert.NoError(t, err)

	c := r.ToTrie()

	t.Log(c.Search("10.0.2.1"))
	t.Log(c.Search("244.178.44.111"))
	t.Log(c.Search("127.0.0.1"))
}
