package latency

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

func TestUDP(t *testing.T) {
	t.Log(DNS(direct.Default, "1.1.1.1:53", "www.google.com"))
}
