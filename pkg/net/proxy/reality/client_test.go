package reality

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

func TestClient(t *testing.T) {
	pp, err := fixed.NewClient(protocol.Fixed_builder{
		Host: proto.String("127.0.0.1"),
		Port: proto.Int32(2096),
	}.Build(), nil)
	assert.NoError(t, err)
	pp, err = NewClient(protocol.Reality_builder{
		ServerName: proto.String("www.baidu.com"),
		ShortId:    proto.String("123456"),
		PublicKey:  proto.String("SOW7P-17ibm_-kz-QUQwGGyitSbsa5wOmRGAigGvDH8"),
	}.Build(), pp)
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
