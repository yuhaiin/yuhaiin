package mux

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"google.golang.org/protobuf/proto"
)

func TestMux(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:4431")
	assert.NoError(t, err)
	defer lis.Close()

	ms := newServer(lis)
	defer ms.Close()

	wg := sync.WaitGroup{}
	wg.Go(func() {

		conn, err := ms.Accept()
		assert.NoError(t, err)

		data, err := io.ReadAll(conn)
		assert.NoError(t, err)

		t.Log(string(data))
	})

	p, err := fixed.NewClient(protocol.Fixed_builder{
		Host: proto.String("127.0.0.1"),
		Port: proto.Int32(4431),
	}.Build(), nil)
	assert.NoError(t, err)

	p, err = NewClient(protocol.Mux_builder{
		Concurrency: proto.Int32(1),
	}.Build(), p)
	assert.NoError(t, err)

	conn, err := p.Conn(context.TODO(), netapi.EmptyAddr)
	assert.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte(time.Now().String()))
	assert.NoError(t, err)

	conn.Close()

	wg.Wait()
}

func TestAddr(t *testing.T) {
	qaddr := &MuxAddr{
		Addr: netapi.EmptyAddr,
		ID:   1,
	}

	addr, err := netapi.ParseAddress("udp", qaddr.String())
	assert.NoError(t, err)

	assert.Equal(t, addr.String(), qaddr.String())
	t.Log(qaddr, addr)
}
