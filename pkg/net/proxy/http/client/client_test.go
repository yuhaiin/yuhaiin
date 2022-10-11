package client

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestClient(t *testing.T) {
	conn, err := NewHttp(&node.PointProtocol_Http{Http: &node.Http{}})(
		simple.NewSimple(proxy.ParseAddressSplit("tcp", "127.0.0.1", proxy.ParsePort(8188)), nil))
	assert.NoError(t, err)

	t.Log(latency.HTTP(conn, "https://www.google.com"))
}
