package inbound

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestHysteria2TLSAutoPersistsCA(t *testing.T) {
	config := contract.Inbound{ID: "hy2", Name: "hy2", Network: contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPUdpOnly}), Protocol: contract.NewTypedProtocol(contract.Hysteria2Protocol{Auth: "secret", UploadBPS: 12500000}), Transports: []contract.Transport{contract.NewTypedTransport(contract.TLSAutoTransport{ServerNames: []string{"test.example"}})}}
	if err := fillGeneratedContractFields(&config); err != nil {
		t.Fatal(err)
	}
	originalCA := bytes.Clone(config.Transports[0].TLSAuto.CACertBase64)
	originalKey := bytes.Clone(config.Transports[0].TLSAuto.CAKeyBase64)
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	storage := store.NewInboundStore(db.DB())
	if err := storage.Save(t.Context(), config, 1); err != nil {
		t.Fatal(err)
	}
	saved, err := storage.Get(t.Context(), config.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fillGeneratedContractFields(&saved); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(saved.Transports[0].TLSAuto.CACertBase64, originalCA) || !bytes.Equal(saved.Transports[0].TLSAuto.CAKeyBase64, originalKey) {
		t.Fatal("CA changed on reload")
	}
	if saved.Protocol.Hysteria2.Auth != "secret" || saved.Protocol.Hysteria2.UploadBPS != 12500000 {
		t.Fatal("lost protocol fields on persistence")
	}
	// Build the QUIC TLS configuration through the actual inbound constructor.
	// Disabled runtime fixtures use a channel handler only to exercise the listener.
	listener, err := listenHysteria2(saved, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
}

func TestHysteria2RejectsUnsupportedTransports(t *testing.T) {
	config := contract.Inbound{ID: "hy2", Network: contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPUdpOnly}), Protocol: contract.NewTypedProtocol(contract.Hysteria2Protocol{Auth: "secret"})}
	for _, transport := range []contract.Transport{contract.NewTypedTransport(contract.MuxTransport{}), contract.NewTypedTransport(contract.HTTP2Transport{}), contract.NewTypedTransport(contract.WebSocketTransport{})} {
		config.Transports = []contract.Transport{transport}
		if server, err := listenHysteria2(config, nil); err == nil {
			_ = server.Close()
			t.Fatalf("accepted %s", transport.Type)
		}
	}
	config.Transports = nil
	if _, err := listenHysteria2(config, nil); err == nil {
		t.Fatal("accepted missing TLS")
	}
}
