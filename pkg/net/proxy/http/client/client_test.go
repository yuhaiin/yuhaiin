package client

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func TestClient(t *testing.T) {
	p := yerror.Must(simple.NewSimple(
		&node.Protocol_Simple{
			Simple: &node.Simple{
				Host: "127.0.0.1",
				Port: 8188,
			},
		})(nil))
	conn, err := NewHttp(&node.Protocol_Http{Http: &node.Http{}})(p)
	assert.NoError(t, err)

	t.Log(latency.HTTP(conn, "https://www.google.com"))
}
