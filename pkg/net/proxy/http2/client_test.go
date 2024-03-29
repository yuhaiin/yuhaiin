package http2

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestClient(t *testing.T) {
	lis, err := dialer.ListenContext(context.TODO(), "tcp", "127.0.0.1:8082")
	assert.NoError(t, err)
	defer lis.Close()

	lis = newServer(lis)

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				t.Error(err)
				break
			}

			go func() {
				defer conn.Close()

				_, _ = io.Copy(io.MultiWriter(os.Stdout, conn), conn)
			}()
		}
	}()

	sm := simple.NewClient(&protocol.Protocol_Simple{
		Simple: &protocol.Simple{
			Host: "127.0.0.1",
			Port: 8082,
		},
	})

	c := NewClient(&protocol.Protocol_Http2{
		Http2: &protocol.Http2{
			Concurrency: 1,
		},
	})

	p, err := sm(nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	p, err = c(p)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	conn, err := p.Conn(context.TODO(), netapi.EmptyAddr)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log("start write bbbb")
	_, err = conn.Write([]byte("bbbb"))
	if err != nil {
		t.Error(err)
		return
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(string(buf[:n]))

	_, err = conn.Write([]byte("ccc"))
	if err != nil {
		t.Error(err)
	}

	n, err = conn.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}

	t.Log(string(buf[:n]))
}

func TestXxx(t *testing.T) {
	for i := 0; i < 100; i++ {
		t.Log(i % 2)
	}
}
