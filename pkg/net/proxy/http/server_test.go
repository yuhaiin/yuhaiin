package http

import (
	"bufio"
	"io"
	"net"
	stdhttp "net/http"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type echoHandler struct{}

func (echoHandler) HandleStream(meta *netapi.StreamMeta) {
	defer meta.Src.Close()
	_, _ = io.Copy(meta.Src, meta.Src)
}
func (echoHandler) HandlePacket(*netapi.Packet) {}
func (echoHandler) HandlePing(*netapi.PingMeta) {}

func TestCONNECTReplaysBufferedTunnelBytes(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ServerConfig{}, netapi.NewListener(lis, nil), echoHandler{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	conn, err := net.DialTimeout("tcp", lis.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\npipelined ClientHello bytes")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := stdhttp.ReadResponse(reader, &stdhttp.Request{Method: stdhttp.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatal(response.Status)
	}
	data := make([]byte, len("pipelined ClientHello bytes"))
	if _, err := io.ReadFull(reader, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "pipelined ClientHello bytes" {
		t.Fatalf("lost bytes: %q", data)
	}
}
