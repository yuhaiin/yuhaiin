package app

import (
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/subscr"
)

func TestLatency(t *testing.T) {
	nodeManager := subscr.NewNodeManager(filepath.Join(config.Path, "node.json"))
	x, err := nodeManager.GetNowNode()
	if err != nil {
		t.Error(err)
	}
	t.Log(Latency(x.NGroup, x.NName))
}
