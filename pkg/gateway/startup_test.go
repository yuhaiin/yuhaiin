package gateway

import (
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestGatewayStartupFailureRemainsRepairableAndRejectsSelectedTraffic(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	for _, test := range []struct{ name, listen, tlsMode string }{
		{name: "unsupported configuration", tlsMode: "unsupported"},
		{name: "occupied listener", listen: occupied.Addr().String()},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := contract.Config{Revision: 7, Gateways: []contract.Gateway{{ID: "web", Name: "Web", Enabled: true, Listen: test.listen, TLSMode: test.tlsMode, Default: contract.Action{Type: "block", Status: 204}}}}
			store := &memoryStore{config: config}
			manager, err := NewManager(t.Context(), store, nil, nil)
			if err != nil {
				t.Fatalf("one failed Gateway prevented application startup: %v", err)
			}
			t.Cleanup(func() { _ = manager.Close() })
			if manager.Status().StartupError == "" {
				t.Fatal("startup failure is not reported")
			}
			if saved := manager.Config(); saved.Revision != 7 || saved.Gateways[0].Listen != test.listen || saved.Gateways[0].TLSMode != test.tlsMode {
				t.Fatalf("failed configuration is not available for repair: %+v", saved)
			}
			server, client := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			if !manager.InterceptGateway(netapi.WithContext(t.Context()), &netapi.StreamMeta{Src: server}, "web") {
				t.Fatal("traffic selected for failed Gateway fell through to ordinary forwarding")
			}
			if _, err := client.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("failed Gateway did not close selected connection: %v", err)
			}
			config = manager.Config()
			config.Gateways[0].Listen, config.Gateways[0].TLSMode = "", "off"
			if _, err := manager.Save(t.Context(), config); err != nil {
				t.Fatal(err)
			}
			if status := manager.Status(); status.StartupError != "" || status.Revision != 8 || len(status.Gateways) != 1 {
				t.Fatalf("repaired Gateway did not activate: %+v", status)
			}
			response := httptest.NewRecorder()
			manager.current.Load().gateways["web"].engine.ServeHTTP(response, httptest.NewRequest("GET", "http://example.test/", nil))
			if response.Code != 204 {
				t.Fatalf("repaired Gateway response: %d", response.Code)
			}
		})
	}
}
