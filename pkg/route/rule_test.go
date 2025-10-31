package route

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestChangePriority(t *testing.T) {
	t.Run("insertBefore", func(t *testing.T) {
		src := []string{
			"a",
			"b",
			"c",
			"d",
			"e",
		}

		t.Log(assert.ObjectsAreEqual([]string{"a", "d", "b", "c", "e"}, InsertBefore(src, 3, 1)))
		t.Log(assert.ObjectsAreEqual([]string{"d", "a", "b", "c", "e"}, InsertBefore(src, 3, 0)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "c", "d", "e"}, InsertBefore(src, 3, 4)))
	})

	t.Run("insertAfter", func(t *testing.T) {
		src := []string{
			"a",
			"b",
			"c",
			"d",
			"e",
		}

		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "d", "c", "e"},
			InsertAfter(src, 3, 1)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "d", "b", "c", "e"},
			InsertAfter(src, 3, 0)))
		t.Log(assert.ObjectsAreEqual([]string{"a", "b", "c", "e", "d"},
			InsertAfter(src, 3, 4)))
	})
}
