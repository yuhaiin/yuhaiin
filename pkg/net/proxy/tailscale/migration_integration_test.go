//go:build !ts_omit_tailnetlock

package tailscale

import (
	"bytes"
	"context"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// Enroll an actual tsnet identity, upgrade it in place, then roll back to tsnet.
// The local control server must continue to see one node with the same keys/IPs.
func TestEnrolledLegacyIdentityMigrationAndRollback(t *testing.T) {
	oldDir := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(oldDir) })
	relayServer := derpserver.New(key.NewNode(), logger.Discard)
	defer relayServer.Close()
	relay := httptest.NewTLSServer(derpserver.Handler(relayServer))
	defer relay.Close()
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(relay.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	stun, stopSTUN := stuntest.Serve(t)
	defer stopSTUN()
	control := &testcontrol.Server{DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1, RegionCode: "local", Nodes: []*tailcfg.DERPNode{{Name: "local", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: port, STUNPort: stun.Port, InsecureForTests: true}}}}}, DNSConfig: &tailcfg.DNSConfig{Proxied: true}, MagicDNSDomain: "migration.ts.net", Logf: logger.Discard}
	control.HTTPTestServer = httptest.NewServer(control)
	defer control.HTTPTestServer.Close()
	config := Config{AuthKey: "local-test-key", Hostname: "migration", ControlURL: control.HTTPTestServer.URL}
	dir, err := statePath(configuration.DataDir.Load(), config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	makeLegacy := func() *tsnet.Server {
		// Only synthetic local services are contacted by this test instance.
		s := &tsnet.Server{Dir: dir, Hostname: config.Hostname, ControlURL: config.ControlURL, AuthKey: config.AuthKey, UserLogf: logger.Discard, Logf: logger.Discard, Tun: newTailnetTun()}
		t.Cleanup(func() { _ = s.Close() })
		if _, err := s.Up(ctx); err != nil {
			t.Fatal(err)
		}
		v4, v6 := s.TailscaleIPs()
		if err := s.Tun.(*tailnetTun).configure(v4, v6); err != nil {
			t.Fatal(err)
		}
		s.AuthKey = ""
		return s
	}
	legacy := makeLegacy()
	before := control.AllNodes()
	if len(before) != 1 {
		t.Fatalf("initial nodes=%d", len(before))
	}
	original := before[0]
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tailscaled.state")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New(config, direct.Default)
	if err != nil {
		t.Fatal(err)
	}
	tc := proxy.(*Tailscale)
	t.Cleanup(func() { _ = tc.Close() })
	if _, err := tc.ready(ctx); err != nil {
		t.Fatal(err)
	}
	assertIdentity := func() {
		t.Helper()
		nodes := control.AllNodes()
		if len(nodes) != 1 || nodes[0].ID != original.ID || nodes[0].Key != original.Key || nodes[0].Machine != original.Machine {
			t.Fatal("migration or rollback registered a new node identity")
		}
		if len(nodes[0].Addresses) != len(original.Addresses) {
			t.Fatal("identity addresses changed")
		}
		for i, ip := range original.Addresses {
			if nodes[0].Addresses[i] != ip {
				t.Fatal("identity addresses changed")
			}
		}
	}
	assertIdentity()
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, raw) {
		t.Fatal("migration modified original legacy state")
	}
	if err := tc.Close(); err != nil {
		t.Fatal(err)
	}
	rollback := makeLegacy()
	assertIdentity()
	if err := rollback.Close(); err != nil {
		t.Fatal(err)
	}
}
