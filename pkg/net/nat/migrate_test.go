package nat

import (
	"net"
	"testing"
)

func TestGenerateID(t *testing.T) {
	t.Log(GenerateID(&net.IPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Zone: "test",
	}))
	t.Log(GenerateID(&net.IPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Zone: "test",
	}))
	t.Log(GenerateID(&net.IPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Zone: "test",
	}))
}
