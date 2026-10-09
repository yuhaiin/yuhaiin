package inbound

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

// TLS is an independent transport: its ALPN must not override the protocol
// selected by the inbound or the next transport in the node chain.
func TestTLSProtocolCompatibility(t *testing.T) {
	ca, err := cert.GenerateCa()
	assert.NoError(t, err)
	caCert, err := ca.CertBytes()
	assert.NoError(t, err)
	caKey, err := ca.PrivateKeyBytes()
	assert.NoError(t, err)

	httpProtocol := contract.NewTypedProtocol(contract.HTTPProtocol{})
	socksProtocol := contract.NewTypedProtocol(contract.Socks5Protocol{})
	mixedProtocol := contract.NewTypedProtocol(contract.MixedProtocol{})
	yuubinsyaProtocol := contract.NewTypedProtocol(contract.YuubinsyaProtocol{Password: "test-password"})
	httpClient := contractnode.Protocol{Type: "http", HTTP: &contractnode.HTTP{}}
	socksClient := contractnode.Protocol{Type: "socks5", Socks5: &contractnode.Socks5{}}
	yuubinsyaClient := contractnode.Protocol{Type: "yuubinsya", Yuubinsya: &contractnode.Yuubinsya{Password: "test-password"}}

	for _, tc := range []struct {
		name       string
		protocol   contract.Protocol
		transports []contract.Transport
		chain      []contractnode.Protocol
	}{
		{name: "http", protocol: httpProtocol, chain: []contractnode.Protocol{httpClient}},
		{name: "socks5", protocol: socksProtocol, chain: []contractnode.Protocol{socksClient}},
		{name: "mixed_http", protocol: mixedProtocol, chain: []contractnode.Protocol{httpClient}},
		{name: "mixed_socks5", protocol: mixedProtocol, chain: []contractnode.Protocol{socksClient}},
		{name: "yuubinsya", protocol: yuubinsyaProtocol, chain: []contractnode.Protocol{yuubinsyaClient}},
		{
			name: "websocket", protocol: yuubinsyaProtocol,
			transports: []contract.Transport{contract.NewTypedTransport(contract.WebSocketTransport{})},
			chain:      []contractnode.Protocol{{Type: "websocket", Websocket: &contractnode.Websocket{Host: "example.com"}}, yuubinsyaClient},
		},
		{
			name: "http2", protocol: yuubinsyaProtocol,
			transports: []contract.Transport{contract.NewTypedTransport(contract.HTTP2Transport{})},
			chain:      []contractnode.Protocol{{Type: "http2", HTTP2: &contractnode.Concurrency{}}, yuubinsyaClient},
		},
		{
			name: "mux", protocol: yuubinsyaProtocol,
			transports: []contract.Transport{contract.NewTypedTransport(contract.MuxTransport{})},
			chain:      []contractnode.Protocol{{Type: "mux", Mux: &contractnode.Concurrency{}}, yuubinsyaClient},
		},
		{
			name: "proxy_protocol", protocol: yuubinsyaProtocol,
			transports: []contract.Transport{contract.NewTypedTransport(contract.ProxyTransport{})},
			chain:      []contractnode.Protocol{{Type: "proxy", Proxy: &contractnode.Proxy{}}, yuubinsyaClient},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, alpn := range []struct {
				name   string
				protos []string
			}{
				{name: "none"},
				{name: "http1", protos: []string{"http/1.1"}},
				{name: "h2", protos: []string{"h2"}},
				{name: "custom", protos: []string{"yuhaiin"}},
			} {
				t.Run(alpn.name, func(t *testing.T) {
					base, err := contractNetwork(contract.Inbound{Network: contract.NewTypedNetwork(contract.TCPUDPNetwork{
						Host: "127.0.0.1:0", UDP: contract.UDPEnabled,
					})})
					assert.NoError(t, err)
					t.Cleanup(func() { base.Close() })
					lis, err := contractTransport(contract.NewTypedTransport(contract.TLSAutoTransport{
						CACertBase64: caCert, CAKeyBase64: caKey,
						ServerNames: []string{"*.example.com"}, NextProtos: alpn.protos,
					}), base)
					assert.NoError(t, err)
					for _, transport := range tc.transports {
						lis, err = contractTransport(transport, lis)
						assert.NoError(t, err)
					}
					handler := &tlsCompatHandler{destination: make(chan string, 1)}
					srv, err := contractProtocol(tc.protocol, lis, handler, [2]netip.Prefix{})
					assert.NoError(t, err)
					t.Cleanup(func() { srv.Close() })

					var client netapi.Proxy = tlsCompatDialer{addr: base.Addr().String()}
					client, err = register.ContractWrap(contractnode.Protocol{Type: "tls", TLS: &contractnode.TLS{
						Enable: true, CACert: [][]byte{caCert},
						ServerNames: []string{"*.example.com"}, NextProtos: alpn.protos,
					}}, client)
					assert.NoError(t, err)
					for _, protocol := range tc.chain {
						client, err = register.ContractWrap(protocol, client)
						assert.NoError(t, err)
					}
					t.Cleanup(func() { client.Close() })
					ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
					defer cancel()
					target, err := netapi.ParseAddress("tcp", "example.com:443")
					assert.NoError(t, err)
					conn, err := client.Conn(ctx, target)
					assert.NoError(t, err)
					defer conn.Close()
					assert.NoError(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
					const payload = "tls-transport-probe"
					_, err = conn.Write([]byte(payload))
					assert.NoError(t, err)
					reply := make([]byte, len(payload))
					_, err = io.ReadFull(conn, reply)
					assert.NoError(t, err)
					assert.Equal(t, string(reply), payload)
					select {
					case destination := <-handler.destination:
						assert.Equal(t, destination, target.String())
					case <-ctx.Done():
						t.Fatal("inbound did not receive the target")
					}
				})
			}
		})
	}
}

type tlsCompatDialer struct {
	netapi.EmptyDispatch
	addr string
}

func (d tlsCompatDialer) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
	if err == nil {
		deadline, _ := ctx.Deadline()
		_ = conn.SetDeadline(deadline)
	}
	return conn, err
}

func (tlsCompatDialer) Close() error { return nil }

func (tlsCompatDialer) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}

func (tlsCompatDialer) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported
}

type tlsCompatHandler struct {
	destination chan string
}

func (h *tlsCompatHandler) HandleStream(meta *netapi.StreamMeta) {
	defer meta.Src.Close()
	h.destination <- meta.Address.String()
	_, _ = io.Copy(meta.Src, meta.Src)
}

func (*tlsCompatHandler) HandlePacket(packet *netapi.Packet) { packet.DecRef() }
func (*tlsCompatHandler) HandlePing(*netapi.PingMeta)        {}
