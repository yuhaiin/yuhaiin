package inbound

import (
	"bytes"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestContractStoreSyncSkipsInvalidStoredInbound(t *testing.T) {
	ctx := t.Context()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := plainstore.NewInboundStore(db.DB())
	if err := store.SaveSettings(ctx, plainstore.InboundSettings{}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a-valid", "z-valid"} {
		config := contract.Inbound{ID: id, Name: id, Enabled: true,
			Network:  contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPTCPOnly}),
			Protocol: contract.NewTypedProtocol(contract.MixedProtocol{})}
		if err := store.Save(ctx, config, 1); err != nil {
			t.Fatal(err)
		}
	}
	legacy := `{"id":"pa","name":"pa","enabled":true,"network":{"type":"tcp_udp","tcp_udp":{"host":"127.0.0.1:0","udp":"tcp_only"}},"protocol":{"type":"reverse_http","reverse_http":{"url":"http://127.0.0.1:3000"}}}`
	if _, err := db.DB().ExecContext(ctx, `INSERT INTO inbounds_v2(id,name,enabled,network_type,protocol_type,transport_types_json,updated_at,data_json) VALUES ('pa','pa',1,'tcp_udp','reverse_http','[]',1,?)`, legacy); err != nil {
		t.Fatal(err)
	}
	runtime := NewInbound(netapi.NewErrProxy(errors.New("unexpected outbound request")))
	t.Cleanup(func() { _ = runtime.Close() })
	contracts := NewContractStore(store, runtime)
	if err := contracts.Sync(ctx); err != nil {
		t.Fatalf("one unsupported inbound prevented valid listeners from starting: %v", err)
	}
	statuses, err := contracts.Statuses(ctx)
	if err != nil || len(statuses) != 3 {
		t.Fatalf("valid inbound statuses unavailable: %+v, %v", statuses, err)
	}
	for _, status := range statuses {
		if status.ID == "pa" {
			if status.Status != "failed" || !strings.Contains(status.LastError, `unknown protocol type "reverse_http"`) {
				t.Fatalf("unsupported inbound failure is not visible: %+v", status)
			}
			continue
		}
		if status.Status != "running" || len(status.Listeners) != 1 {
			t.Fatalf("valid inbound is not running: %+v", status)
		}
		client, err := net.DialTimeout("tcp", status.Listeners[0].Listen, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		_, writeErr := client.Write([]byte{5, 1, 0})
		var response [2]byte
		_, readErr := io.ReadFull(client, response[:])
		_ = client.Close()
		if writeErr != nil || readErr != nil || !bytes.Equal(response[:], []byte{5, 0}) {
			t.Fatalf("valid inbound cannot complete SOCKS5 greeting: %x, %v, %v", response, writeErr, readErr)
		}
	}
	if config, err := contracts.Get(ctx, "pa"); err != nil || config.Protocol.Type != "reverse_http" {
		t.Fatalf("unsupported inbound is not available for inspection: %+v, %v", config, err)
	}
	if events, err := contracts.Events(ctx, "pa"); err != nil || len(events) != 1 || events[0].State != "failed" {
		t.Fatalf("unsupported inbound failure event is not available: %+v, %v", events, err)
	}
	var stored string
	if err := db.DB().QueryRowContext(ctx, `SELECT data_json FROM inbounds_v2 WHERE id='pa'`).Scan(&stored); err != nil || stored != legacy {
		t.Fatalf("unsupported configuration was changed: %q, %v", stored, err)
	}
}
