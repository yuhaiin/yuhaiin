package process

import (
	"github.com/Asutorufa/yuhaiin/subscr"
	"testing"
)

func TestLatency(t *testing.T) {
	x, err := subscr.GetNowNode()
	if err != nil {
		t.Error(err)
	}
	switch x.(type) {
	case *subscr.Shadowsocks:
		t.Log(Latency(x.(*subscr.Shadowsocks).Group, x.(*subscr.Shadowsocks).Name))
	}
}
