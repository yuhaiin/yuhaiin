package aead

import (
	"context"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

func TestPacket(t *testing.T) {
	s, err := fixed.NewServer(listener.Tcpudp_builder{
		Host:    proto.String(":12345"),
		Control: listener.TcpUdpControl_disable_tcp.Enum(),
	}.Build())
	assert.NoError(t, err)

	as, err := NewServer(listener.Aead_builder{
		Password: proto.String("123456"),
	}.Build(), s)
	assert.NoError(t, err)

	pc, err := as.Packet(context.Background())
	assert.NoError(t, err)
	defer pc.Close()

	go func() {
		var buf [1024]byte
		for {
			n, addr, err := pc.ReadFrom(buf[:])
			if err != nil {
				break
			}

			t.Log("read from", addr, "data", string(buf[:n]))
		}
	}()

	fp, err := fixed.NewClient(protocol.Fixed_builder{
		Host: proto.String("127.0.0.1"),
		Port: proto.Int32(12345),
	}.Build(), nil)
	assert.NoError(t, err)
	defer fp.Close()

	ac, err := NewClient(protocol.Aead_builder{
		Password: proto.String("123456"),
	}.Build(), fp)
	assert.NoError(t, err)
	defer ac.Close()

	pc, err = ac.PacketConn(context.Background(), netapi.EmptyAddr)
	assert.NoError(t, err)
	defer pc.Close()

	pc.WriteTo([]byte("hello"), netapi.EmptyAddr)

	time.Sleep(time.Second)
}
