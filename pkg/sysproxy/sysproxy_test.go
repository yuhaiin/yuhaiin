package sysproxy

import (
	"strings"
	"testing"
)

func TestPr(t *testing.T) {
	t.Log(strings.Join(priAddr, ";"))
	t.Log(replaceUnspecified(":1080"))
}
