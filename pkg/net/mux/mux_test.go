package mux

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestMux(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:4431")
	assert.NoError(t, err)
	defer lis.Close()

	ms := NewServer(lis)
	defer ms.Close()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, err := ms.Accept()
		assert.NoError(t, err)

		data, err := io.ReadAll(conn)
		assert.NoError(t, err)

		t.Log(string(data))
	}()

	p, err := simple.New(&protocol.Protocol_Simple{
		Simple: &protocol.Simple{
			Host: "127.0.0.1",
			Port: 4431,
		},
	})(nil)
	assert.NoError(t, err)

	p, err = NewClient(nil)(p)
	assert.NoError(t, err)

	conn, err := p.Conn(context.TODO(), netapi.EmptyAddr)
	assert.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte(time.Now().String()))
	assert.NoError(t, err)

	conn.Close()

	wg.Wait()
}

func TestMuxConn(t *testing.T) {
	var rw io.ReadWriteCloser = &muxConn{}

	if _, ok := rw.(interface{ CloseWrite() error }); ok {
		t.Log(ok)
	}
}
