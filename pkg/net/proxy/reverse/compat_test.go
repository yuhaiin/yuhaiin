package reverse

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type forwardingHandler struct{}

func (forwardingHandler) HandleStream(meta *netapi.StreamMeta) {
	defer meta.Src.Close()
	remote, err := net.DialTimeout("tcp", meta.Address.String(), time.Second)
	if err != nil {
		return
	}
	defer remote.Close()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(remote, meta.Src); _ = remote.Close(); close(done) }()
	_, _ = io.Copy(meta.Src, remote)
	_ = meta.Src.Close()
	<-done
}
func (forwardingHandler) HandlePacket(*netapi.Packet) {}
func (forwardingHandler) HandlePing(*netapi.PingMeta) {}

func TestLegacyReverseHTTPUsesGateway(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "public.example" || r.URL.Path != "/base/path" {
			t.Errorf("host=%s path=%s", r.Host, r.URL.Path)
		}
		_, _ = io.WriteString(w, "legacy works")
	}))
	defer up.Close()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewHTTPServer(HTTPServerConfig{URL: up.URL + "/base"}, netapi.NewListener(lis, nil), forwardingHandler{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	request, _ := http.NewRequestWithContext(t.Context(), "GET", "http://"+lis.Addr().String()+"/path", nil)
	request.Host = "public.example"
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != "legacy works" {
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
}

type terminationProxy struct {
	netapi.Proxy
	destination string
}

func (p terminationProxy) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	return new(net.Dialer).DialContext(ctx, "tcp", p.destination)
}

func TestLegacyHTTPTerminationTypedTLSMetadata(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Legacy") != "yes" {
			t.Errorf("missing configured header: %v", r.Header)
		}
		_, _ = io.WriteString(w, "typed TLS state")
	}))
	defer up.Close()
	// The surrounding legacy outbound chain owns TLS. This mock supplies the
	// plaintext side of that chain, so a second TLS handshake would fail.
	p, err := NewHttpTermination(Config{Headers: map[string]HTTPHeaders{"example.com": {Headers: []HTTPHeader{{Key: "X-Legacy", Value: "yes"}}}}}, terminationProxy{destination: strings.TrimPrefix(up.URL, "http://")})
	if err != nil {
		t.Fatal(err)
	}
	// The adapter owns its parent proxy in production; the mock only implements Conn.
	u := p.(*httpTermination)
	defer u.ch.Close()
	defer u.server.Close()
	defer u.engine.Close()
	address, _ := netapi.ParseAddress("tcp", "example.com:443")
	conn, err := u.Conn(netapi.WithContext(t.Context()), address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.(*wrapConn).SetTLSTermination(true)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "typed TLS state") {
		t.Fatalf("response=%s", data)
	}
}
