package latency

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
)

func TestTCP(t *testing.T) {
	t.Log(HTTP(direct.Default, "https://www.baidu.com"))
}
