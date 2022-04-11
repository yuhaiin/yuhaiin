package latency

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
)

func TestTCP(t *testing.T) {
	t.Log(HTTP(&proxy.DefaultProxy{}, "https://www.baidu.com"))
}
