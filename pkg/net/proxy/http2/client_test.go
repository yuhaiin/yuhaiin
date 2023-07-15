package http2

import (
	"context"
	"log"
	"testing"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/simple"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

func TestClient(t *testing.T) {
	sm := simple.New(&protocol.Protocol_Simple{
		Simple: &protocol.Simple{
			Host: "127.0.0.1",
			Port: 8082,
		},
	})

	c := NewClient(&protocol.Protocol_Http2{
		Http2: &protocol.Http2{
			Host: "www.github.com",
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

	conn, err := p.Conn(context.TODO(), proxy.EmptyAddr)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	log.Println("start write bbbb")
	_, err = conn.Write([]byte("bbbb"))
	if err != nil {
		t.Error(err)
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
