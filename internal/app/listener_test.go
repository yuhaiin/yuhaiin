package app

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

func TestRef(t *testing.T) {
	if ref[hTTP] == nil {
		t.Log("nil")
	} else {
		t.Log("not nil")
	}
	if ref[100] == nil {
		t.Log("nil")
	} else {
		t.Log("not nil")
	}

	var x interface{}
	if _, ok := x.(proxy.UDPServer); !ok {
		t.Log("nil")
	}
}
