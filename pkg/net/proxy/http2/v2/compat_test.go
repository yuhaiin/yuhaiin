package http2

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	ytls "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
)

type implementation struct {
	name      string
	newClient func(Config, netapi.Proxy) (netapi.Proxy, error)
	newServer func(ServerConfig, netapi.Listener) (netapi.Listener, error)
}

func TestCompatibility(t *testing.T) {
	v2 := implementation{
		name:      "v2",
		newClient: NewClient,
		newServer: NewServer,
	}

	for _, server := range []implementation{v2} {
		for _, client := range []implementation{v2} {
			name := fmt.Sprintf("client_%s_server_%s", client.name, server.name)
			t.Run(name, func(t *testing.T) {
				timeout := 5 * time.Second
				ctx, cancel := context.WithTimeout(t.Context(), timeout)
				defer cancel()

				listener, err := nettest.NewLocalListener("tcp")
				assert.NoError(t, err)
				baseListener := netapi.NewListener(listener, nil)

				srv, err := server.newServer(ServerConfig{}, baseListener)
				assert.NoError(t, err)
				defer srv.Close()

				host, portString, err := net.SplitHostPort(srv.Addr().String())
				assert.NoError(t, err)
				port, err := strconv.ParseUint(portString, 10, 16)
				assert.NoError(t, err)

				proxy, err := fixed.NewClient(fixed.Config{Host: host, Port: int32(port)}, nil)
				assert.NoError(t, err)
				clientProxy, err := client.newClient(Config{Concurrency: 1}, proxy)
				assert.NoError(t, err)
				defer clientProxy.Close()

				clientConn, err := clientProxy.Conn(ctx, netapi.EmptyAddr)
				assert.NoError(t, err)
				defer clientConn.Close()

				serverConn, err := acceptWithContext(ctx, srv)
				assert.NoError(t, err)
				defer serverConn.Close()

				assert.NoError(t, clientConn.SetDeadline(time.Now().Add(timeout)))
				assert.NoError(t, serverConn.SetDeadline(time.Now().Add(timeout)))

				const request = "client-to-server"
				const response = "server-to-client"

				_, err = clientConn.Write([]byte(request))
				assert.NoError(t, err)
				buf := make([]byte, len(request))
				_, err = io.ReadFull(serverConn, buf)
				assert.NoError(t, err)
				assert.Equal(t, string(buf), request)

				_, err = serverConn.Write([]byte(response))
				assert.NoError(t, err)
				buf = make([]byte, len(response))
				_, err = io.ReadFull(clientConn, buf)
				assert.NoError(t, err)
				assert.Equal(t, string(buf), response)
			})
		}
	}
}

func TestCompatibilityOverTLS(t *testing.T) {
	ca, err := cert.GenerateCa()
	assert.NoError(t, err)
	caCert, err := ca.CertBytes()
	assert.NoError(t, err)
	caKey, err := ca.PrivateKeyBytes()
	assert.NoError(t, err)

	for _, tc := range []struct {
		name string
		alpn []string
	}{
		{name: "no_alpn"},
		{name: "h2", alpn: []string{"h2"}},
		{name: "custom_alpn", alpn: []string{"yuhaiin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			assert.NoError(t, err)
			t.Cleanup(func() { listener.Close() })
			tlsListener, err := ytls.NewTlsAutoServer(ytls.TlsAutoServerConfig{
				CACert: caCert, CAKey: caKey,
				ServerNames: []string{"*.example.com"}, NextProtos: tc.alpn,
			}, netapi.NewListener(listener, nil))
			assert.NoError(t, err)
			srv, err := NewServer(ServerConfig{}, tlsListener)
			assert.NoError(t, err)
			t.Cleanup(func() { srv.Close() })

			tlsProxy, err := ytls.NewClient(ytls.TLSConfig{
				Enable: true, CACert: [][]byte{caCert},
				ServerNames: []string{"*.example.com"}, NextProtos: tc.alpn,
			}, &addressDialer{addr: listener.Addr().String()})
			assert.NoError(t, err)
			client, err := NewClient(Config{}, tlsProxy)
			assert.NoError(t, err)
			t.Cleanup(func() { client.Close() })

			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			conn, err := client.Conn(ctx, netapi.EmptyAddr)
			assert.NoError(t, err)
			defer conn.Close()
			serverConn, err := acceptWithContext(ctx, srv)
			assert.NoError(t, err)
			defer serverConn.Close()
			go func() { _, _ = io.Copy(serverConn, serverConn) }()
			assertTunnelEcho(t, conn)
		})
	}
}

func TestContractRegistrationUsesV2(t *testing.T) {
	proxy, err := register.ContractWrap(contractnode.Protocol{
		Type:  "http2",
		HTTP2: &contractnode.Concurrency{Concurrency: 1},
	}, netapi.NewErrProxy(io.ErrClosedPipe))
	assert.NoError(t, err)
	_, ok := proxy.(*Client)
	assert.Equal(t, ok, true)
	assert.NoError(t, proxy.Close())
}

func acceptWithContext(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		resultCh <- result{conn: conn, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
