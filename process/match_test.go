package process

import (
	"testing"
)

func TestReadline(t *testing.T) {
	modes := map[string]int{"direct": 0, "proxy": 1, "block": 2}
	t.Log(modes["test"], modes["direct"], modes["block"], modes["block2"])
}
