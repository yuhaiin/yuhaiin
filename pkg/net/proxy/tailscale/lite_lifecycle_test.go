package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/register"
)

func TestLiteRegistrationAndLazyLifetime(t *testing.T) {
	upstream := netapi.NewErrProxy(errors.New("upstream must stay untouched"))
	p, err := register.ContractWrap(contract.Protocol{Type: "tailscale-lite", TailscaleLite: &contract.TailscaleLite{AuthKey: "test-key"}}, upstream)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	node, ok := p.(*Lite)
	if !ok {
		t.Fatalf("registered %T", p)
	}
	if node.NodeRuntimeStatus().State != "idle" {
		t.Fatal("new node was initialized")
	}
	addr := netapi.ParseNetipAddr("tcp", netip.MustParseAddr("192.0.2.1"), 443)
	if _, err := p.Conn(netapi.WithBackgroundProbe(t.Context()), addr); !errors.Is(err, netapi.ErrBackgroundProbeUnavailable) {
		t.Fatal(err)
	}
	if node.client != nil || node.owner.tsnet != nil || node.owner.stateDir != "" {
		t.Fatal("background probe created an identity")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.Conn(ctx, addr); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	node.owner.mu.Lock()
	done := make(chan error, 1)
	go func() {
		if node.NodeRuntimeStatus().State != "connecting" {
			done <- errors.New("busy init not reported")
			return
		}
		_, err := node.init(netapi.WithBackgroundProbe(t.Context()))
		done <- err
	}()
	select {
	case err := <-done:
		node.owner.mu.Unlock()
		if !errors.Is(err, netapi.ErrBackgroundProbeUnavailable) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		node.owner.mu.Unlock()
		t.Fatal("background probe waited behind initialization")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if node.NodeRuntimeStatus().State != "closed" {
		t.Fatal("closed node not reported")
	}
	if _, err := node.init(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	legacy, err := register.ContractWrap(contract.Protocol{Type: "tailscale", Tailscale: &contract.Tailscale{AuthKey: "test-key"}}, upstream)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if _, ok := legacy.(*Tailscale); !ok {
		t.Fatalf("legacy runtime replaced by %T", legacy)
	}
}

func TestLiteStateIsIndependentAndRecoveryDoesNotInitialize(t *testing.T) {
	base := t.TempDir()
	input := contract.TailscaleLite{AuthKey: "test-key", Hostname: "same-host"}
	current, err := LiteRecoveryDirectory(base, input)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := RecoveryDirectory(base, contract.Tailscale(input))
	if err != nil || current == legacy {
		t.Fatal("runtimes share identity", err)
	}
	files, err := LiteRecoveryFiles(base, input)
	if err != nil || len(files) != 0 {
		t.Fatal(files, err)
	}
	if entries, err := os.ReadDir(base); err != nil || len(entries) != 0 {
		t.Fatal("inventory wrote identity storage", err)
	}
	for _, dir := range []string{current, legacy} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"lite.json", "tailscaled.state", "ignored.log"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("test-identity"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	files, err = LiteRecoveryFiles(base, input)
	if err != nil || len(files) != 1 || files[0] != filepath.Join(current, "lite.json") {
		t.Fatal(files, err)
	}
	input.AuthKey = "other-key"
	if files, err := LiteRecoveryFiles(base, input); err != nil || len(files) != 0 {
		t.Fatal("selected another identity", files, err)
	}
}
