package app

import (
	"testing"

	server "github.com/Asutorufa/yuhaiin/pkg/net/proxy/server"
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
	if _, ok := x.(server.UDPServer); !ok {
		t.Log("nil")
	}
}
