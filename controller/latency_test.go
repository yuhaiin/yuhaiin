package controller

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/subscr/shadowsocks"

	"github.com/Asutorufa/yuhaiin/subscr"
)

func TestLatency(t *testing.T) {
	x, err := subscr.GetNowNode()
	if err != nil {
		t.Error(err)
	}
	switch x.(type) {
	case *shadowsocks.Shadowsocks:
		t.Log(Latency(x.(*shadowsocks.Shadowsocks).NGroup, x.(*shadowsocks.Shadowsocks).NName))
	}
}
