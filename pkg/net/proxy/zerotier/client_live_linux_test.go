//go:build linux && !android && (amd64 || arm64)

// TestPodmanLiveConnectivity is an opt-in end-to-end test against an authorized
// native ZeroTier peer running in Podman.
package zerotier

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func TestPodmanLiveConnectivity(t *testing.T) {
	networkID := os.Getenv("ZT_TEST_NETWORK_ID")
	target := os.Getenv("ZT_TEST_TARGET")
	udpTarget := os.Getenv("ZT_TEST_UDP_TARGET")
	idFile := os.Getenv("ZT_TEST_NODE_ID_FILE")
	if networkID == "" || target == "" || udpTarget == "" || idFile == "" {
		t.Skip("requires the Podman ZeroTier test network")
	}

	oldDir := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(oldDir) })

	proxy, err := register.ContractDialer(contractnode.Node{
		ID: "codex-podman-live-e2e", Name: "Podman ZeroTier live test", Origin: "test",
		Chain: []contractnode.Protocol{{
			Type:     "zerotier",
			ZeroTier: &contractnode.ZeroTier{NetworkID: networkID, Identity: "codex-podman-e2e"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := proxy.(*Client)
	t.Cleanup(func() { _ = client.Close() })

	address, err := client.node.Address()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idFile, []byte(fmt.Sprintf("%010x", address)), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	for {
		client.mu.RLock()
		active := client.active != nil
		client.mu.RUnlock()
		if active {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("ZeroTier network never became usable: %v", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}

	addr, err := netapi.ParseAddress("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.Conn(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: zerotier-test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "zt-e2e-ok") {
		t.Fatalf("unexpected response: status=%d body=%q", response.StatusCode, body)
	}

	udpAddress, err := netapi.ParseAddress("udp", udpTarget)
	if err != nil {
		t.Fatal(err)
	}
	udpRemote, ok := udpAddress.(netapi.IPAddress)
	if !ok {
		t.Fatalf("UDP target %q did not parse as an IP address", udpTarget)
	}
	packetConn, err := client.PacketConn(ctx, udpAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	if _, err := packetConn.WriteTo([]byte("e2e"), net.UDPAddrFromAddrPort(udpRemote.AddrPort())); err != nil {
		t.Fatal(err)
	}
	if err := packetConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	udpResponse := make([]byte, 128)
	n, _, err := packetConn.ReadFrom(udpResponse)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(udpResponse[:n]); got != "zt-udp-ok:e2e" {
		t.Fatalf("UDP response = %q, want %q", got, "zt-udp-ok:e2e")
	}
}
