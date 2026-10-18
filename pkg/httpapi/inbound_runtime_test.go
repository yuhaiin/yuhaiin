package httpapi

import (
	json "encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestInboundRuntimeRPCReportsFailedStartAndRetriesPersistedConfiguration(t *testing.T) {
	db, err := storagesqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := inbound.NewInbound(netapi.NewErrProxy(errors.New("unused test proxy")))
	t.Cleanup(func() { _ = runtime.Close(); _ = db.Close() })
	configStore := inbound.NewContractStore(plainstore.NewInboundStore(db.DB()), runtime)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })
	config := contract.Inbound{ID: "local", Name: "Local proxy", Enabled: true, Network: contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: occupied.Addr().String(), UDP: contract.UDPDisabled}), Protocol: contract.NewTypedProtocol(contract.MixedProtocol{})}
	if err := configStore.Save(t.Context(), config, 0); err == nil {
		t.Fatal("occupied port accepted")
	}
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if err := handler(w, r); err != nil {
				t.Errorf("handler: %v", err)
			}
		})
	}, V2Services{Inbounds: configStore})
	call := func(operation, body string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/"+operation, strings.NewReader(body)))
		return response
	}
	status := func() contract.RuntimeStatus {
		t.Helper()
		response := call("inbounds.status", "{}")
		if response.Code != http.StatusOK {
			t.Fatalf("status: %d %s", response.Code, response.Body.String())
		}
		var result struct {
			Items []contract.RuntimeStatus `json:"items"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Items) != 1 {
			t.Fatalf("statuses: %+v", result)
		}
		return result.Items[0]
	}
	if failed := status(); failed.Status != "failed" || failed.LastError == "" {
		t.Fatalf("failed start hidden: %+v", failed)
	}
	if err := occupied.Close(); err != nil {
		t.Fatal(err)
	}
	response := call("inbound.retry", `{"id":"local"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", response.Code, response.Body.String())
	}
	ready := status()
	if ready.Status != "running" || ready.LastError != "" || ready.Statistics.AcceptedStreams != "0" || ready.Listeners[0].Listen != config.Network.TCPUDP.Host {
		t.Fatalf("retry status: %+v", ready)
	}
	client, err := net.DialTimeout("tcp", config.Network.TCPUDP.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil {
		t.Fatal("TCP-only mixed listener did not provide SOCKS5", err)
	}
	if greeting != [2]byte{5, 0} {
		t.Fatalf("greeting: %v", greeting)
	}
	_ = client.Close()
	response = call("inbound.events", `{"id":"local"}`)
	var events struct {
		Items []contract.RuntimeEvent `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events.Items) < 3 || events.Items[0].Type != "ready" {
		t.Fatalf("events: %+v", events)
	}
	for _, op := range []string{"inbound.events", "inbound.retry"} {
		if response := call(op, `{"id":"missing"}`); response.Code != http.StatusNotFound {
			t.Fatalf("missing %s: %d", op, response.Code)
		}
	}
	config.Enabled = false
	if err := configStore.Save(t.Context(), config, 0); err != nil {
		t.Fatal(err)
	}
	if got := status(); got.Status != "disabled" || got.Enabled {
		t.Fatalf("disabled: %+v", got)
	}
}
