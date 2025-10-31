package share

import (
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/cache"
)

func TestCache(t *testing.T) {
	defer func() {
		_ = os.Remove("tmp.db")
		_ = os.Remove("tmp.socket")
	}()

	c1 := NewShareCache("tmp.db", "tmp.socket")
	defer c1.Close()

	c1c := NewCache(c1, "a")

	err := c1c.Put(cache.Element([]byte("aa"), []byte("dd")))
	assert.NoError(t, err)

	c := NewShareCache("tmp.db", "tmp.socket")
	defer c.Close()

	cc := NewCache(c, "a")

	err = cc.Put(cache.Element([]byte("cc"), []byte("bb")))
	assert.NoError(t, err)

	for _, k := range []string{"aa", "cc"} {
		v, err := cc.Get([]byte(k))
		assert.NoError(t, err)
		t.Log(string(v))
	}

	err = cc.Range(func(key, value []byte) bool {
		t.Log("range", string(key), string(value))
		return true
	})
	assert.NoError(t, err)
}
