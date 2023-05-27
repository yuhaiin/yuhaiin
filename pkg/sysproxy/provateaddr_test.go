package sysproxy

import (
	"fmt"
	"strings"
	"testing"
)

func TestGnome(t *testing.T) {
	t.Log(fmt.Sprintf("['%s']", strings.Join(priAddr, "','")))
}
