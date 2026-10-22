package mixed

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func TestUserAuthenticationDisablesSOCKS4Bypass(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	verify := func(context.Context, string, []byte) (*proxyauth.Identity, error) {
		return nil, proxyauth.ErrUnauthorized
	}
	server, err := NewServer(ServerConfig{Username: "legacy", Password: "required-password", AuthenticateHTTP: verify, AuthenticateSocks5: verify}, netapi.NewListener(listener, nil), netapi.NewChannelHandler(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = conn.Write(append([]byte{4, 1, 0, 80, 127, 0, 0, 1}, []byte("legacy\x00")...))
	if err != nil {
		t.Fatal(err)
	}
	var reply [8]byte
	if _, err = io.ReadFull(conn, reply[:]); err == nil && reply[1] == 0x5a {
		t.Fatal("SOCKS4 bypassed user authentication with only a username")
	}
}
