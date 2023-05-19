package httpproxy

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func TestClient(t *testing.T) {
	p := yerror.Must(simple.New(
		&protocol.Protocol_Simple{
			Simple: &protocol.Simple{
				Host: "127.0.0.1",
				Port: 8188,
			},
		})(nil))
	conn, err := NewClient(&protocol.Protocol_Http{Http: &protocol.Http{}})(p)
	assert.NoError(t, err)

	t.Log(latency.HTTP(conn, "https://www.google.com"))
}
