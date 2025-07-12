package sysproxy

import (
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestPr(t *testing.T) {
	t.Log(strings.Join(priAddr, ";"))
	host, port := replaceUnspecified(":1080")
	assert.Equal(t, "127.0.0.1", host)
	assert.Equal(t, "1080", port)
}
