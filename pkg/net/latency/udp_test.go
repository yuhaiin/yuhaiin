package latency

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

func TestUDP(t *testing.T) {
	t.Log(DNS(&proxy.DefaultProxy{}, "1.1.1.1:53", "www.google.com"))
}
