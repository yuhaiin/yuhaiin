package reality

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestClient(t *testing.T) {
	sm := simple.NewClient(&protocol.Protocol_Simple{
		Simple: &protocol.Simple{
			Host: "127.0.0.1",
			Port: 2096,
		},
	})

	c := NewRealityClient(
		&protocol.Protocol_Reality{
			Reality: &protocol.Reality{
				ServerName: "www.baidu.com",
				ShortId:    "123456",
				PublicKey:  "SOW7P-17ibm_-kz-QUQwGGyitSbsa5wOmRGAigGvDH8",
			},
		},
	)

	pp, err := sm(nil)
	assert.NoError(t, err)
	pp, err = c(pp)
	assert.NoError(t, err)

	conn, err := pp.Conn(context.Background(), netapi.EmptyAddr)
	assert.NoError(t, err)
	defer conn.Close()

	_, _ = conn.Write([]byte("aaa"))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	assert.NoError(t, err)

	t.Log(string(buf[:n]))
}
