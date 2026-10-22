package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

type userHTTPHandler struct{ received chan string }

func (h userHTTPHandler) HandleStream(meta *netapi.StreamMeta) {
	defer meta.Src.Close()
	id := "legacy"
	if meta.Identity != nil {
		id = meta.Identity.UserID
	}
	h.received <- id
	reader := bufio.NewReader(meta.Src)
	for {
		request, err := stdhttp.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = request.Body.Close()
		if request.Header.Get("Proxy-Authorization") != "" {
			_, _ = io.WriteString(meta.Src, "HTTP/1.1 500 Leaked Credentials\r\nContent-Length: 0\r\n\r\n")
			return
		}
		_, _ = fmt.Fprintf(meta.Src, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(id), id)
	}
}
func (userHTTPHandler) HandlePacket(*netapi.Packet) {}
func (userHTTPHandler) HandlePing(*netapi.PingMeta) {}
func TestHTTPUserRequestsDoNotReuseAnotherIdentity(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	verify := func(_ context.Context, user string, proof []byte) (*proxyauth.Identity, error) {
		if string(proof) != "secret" {
			return nil, proxyauth.ErrUnauthorized
		}
		return &proxyauth.Identity{UserID: user, CredentialID: user, Context: t.Context()}, nil
	}
	received := make(chan string, 4)
	server, err := NewServer(ServerConfig{Authenticate: verify}, netapi.NewListener(lis, nil), userHTTPHandler{received})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	conn, err := net.DialTimeout("tcp", lis.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	for _, user := range []string{"alice", "bob", "alice"} {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":secret"))
		_, _ = fmt.Fprintf(conn, "GET http://example.com/test HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
		response, err := stdhttp.ReadResponse(reader, &stdhttp.Request{Method: "GET"})
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != 200 || string(body) != user {
			t.Fatalf("response %s %q: %v", response.Status, body, err)
		}
		select {
		case got := <-received:
			if got != user {
				t.Fatalf("dial identity=%s want=%s", got, user)
			}
		case <-time.After(time.Second):
			t.Fatal("request reused another identity")
		}
	}
	// With empty legacy fields, enabling user authentication still requires auth.
	_, _ = io.WriteString(conn, "GET http://example.com/test HTTP/1.1\r\nHost: example.com\r\n\r\n")
	response, err := stdhttp.ReadResponse(reader, &stdhttp.Request{Method: "GET"})
	if err != nil || response.StatusCode != 407 {
		t.Fatalf("anonymous response %+v: %v", response, err)
	}
	_ = response.Body.Close()
}
