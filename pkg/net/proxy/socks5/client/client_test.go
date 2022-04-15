package client

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

func TestImplement(t *testing.T) {
	// make sure implement
	var _ proxy.Proxy = new(client)
}
