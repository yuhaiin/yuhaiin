package mock

import (
	"context"
	"crypto/rand"
	"net"
	"strconv"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
)

func TestMock(t *testing.T) {
	lis, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)
	defer lis.Close()

	l, err := NewServer(&listener.HttpMock{}, netapi.NewListener(lis, nil))
	assert.NoError(t, err)
	defer l.Close()

	lis, err = l.Stream(context.Background())
	assert.NoError(t, err)
	defer lis.Close()

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()

				var buf [2048]byte
				n, err := conn.Read(buf[:])
				assert.NoError(t, err)

				_, err = conn.Write(buf[:n])
				assert.NoError(t, err)
			}()
		}
	}()

	host, portstr, err := net.SplitHostPort(lis.Addr().String())
	assert.NoError(t, err)

	port, err := strconv.Atoi(portstr)
	assert.NoError(t, err)

	s, err := fixed.NewClient(protocol.Fixed_builder{
		Host: proto.String(host),
		Port: proto.Int32(int32(port)),
	}.Build(), nil)
	assert.NoError(t, err)
	defer s.Close()

	c, err := NewClient(&protocol.HttpMock{}, s)
	assert.NoError(t, err)
	defer c.Close()

	conn, err := c.Conn(context.Background(), netapi.EmptyAddr)
	assert.NoError(t, err)
	defer conn.Close()

	data := make([]byte, 1024)
	_, err = rand.Read(data)
	assert.NoError(t, err)

	_, err = conn.Write(data)
	assert.NoError(t, err)

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	assert.NoError(t, err)

	assert.ObjectsAreEqual(data, buf[:n])
}
