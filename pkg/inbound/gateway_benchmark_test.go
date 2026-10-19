package inbound

import (
	"context"
	"io"
	"net"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type emptyGatewayStore struct{}

func (emptyGatewayStore) Load(context.Context) (contract.Config, error) {
	return contract.Config{}, nil
}
func (emptyGatewayStore) Save(_ context.Context, c contract.Config) (contract.Config, error) {
	return c, nil
}

type echoGatewayProxy struct{ netapi.Proxy }

func (echoGatewayProxy) Conn(context.Context, netapi.Address) (net.Conn, error) {
	left, right := net.Pipe()
	go func() { defer left.Close(); _, _ = io.Copy(left, left) }()
	return right, nil
}

// Compare actual common-handler forwarding with no hook and with the optional
// Gateway installed but disabled. Both include one connection lifecycle and a
// 4 KiB echo over in-memory streams, rather than an encrypted remote topology.
func BenchmarkGatewayDisabledTCPForwarding(b *testing.B) {
	for _, installed := range []bool{false, true} {
		name := "WithoutHook"
		if installed {
			name = "DisabledGateway"
		}
		b.Run(name, func(b *testing.B) {
			h := NewHandler(echoGatewayProxy{})
			defer h.Close()
			if installed {
				manager, err := gateway.NewManager(b.Context(), emptyGatewayStore{}, nil, nil)
				if err != nil {
					b.Fatal(err)
				}
				defer manager.Close()
				h.interceptor = manager
			}
			destination, _ := netapi.ParseAddress("tcp", "example.com:80")
			payload := make([]byte, 4096)
			response := make([]byte, len(payload))
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				left, right := net.Pipe()
				done := make(chan struct{})
				ctx := netapi.WithContext(b.Context())
				go func() { h.Stream(ctx, &netapi.StreamMeta{Src: left, Address: destination}); close(done) }()
				if _, err := right.Write(payload); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(right, response); err != nil {
					b.Fatal(err)
				}
				_ = right.Close()
				<-done
			}
		})
	}
}
