//go:build !ts_omit_tailnetlock

package tailscale

import (
	"context"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func TestLiteAndTSNetCoexist(t *testing.T) {
	old := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	t.Cleanup(func() { configuration.DataDir.Store(old) })
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
	stunAddr, stop := stuntest.Serve(t)
	defer stop()
	control := &testcontrol.Server{DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1, RegionCode: "local", Nodes: []*tailcfg.DERPNode{{Name: "local", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: port, STUNPort: stunAddr.Port, InsecureForTests: true}}}}}, DNSConfig: &tailcfg.DNSConfig{Proxied: true}, MagicDNSDomain: "coexist.ts.net", Logf: logger.Discard}
	control.HTTPTestServer = httptest.NewServer(control)
	defer control.HTTPTestServer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cfg := Config{AuthKey: "local-test-key", Hostname: "same-host", ControlURL: control.HTTPTestServer.URL}
	legacy, err := New(cfg, direct.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	p, err := NewLite(cfg, direct.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	node := p.(*Lite)
	server, err := legacy.(*Tailscale).ready(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client, err := node.ready(ctx)
	if err != nil {
		t.Fatal(err)
	}
	legacyIP, _ := server.TailscaleIPs()
	var liteIP netip.Addr
	for _, prefix := range client.Snapshot().Addresses {
		if prefix.Addr().Is4() {
			liteIP = prefix.Addr()
		}
	}
	if !liteIP.IsValid() || liteIP == legacyIP || node.owner.stateDir == legacy.(*Tailscale).stateDir {
		t.Fatal("runtimes share identity or addresses")
	}
	for {
		all := control.AllNodes()
		registered := len(all) == 2
		for _, n := range all {
			registered = registered && relayServer.IsClientConnectedForTest(n.Key)
		}
		_, route := client.Route(legacyIP)
		_, legacyErr := resolveAddr(ctx, server, "tcp", netapi.ParseNetipAddr("tcp", liteIP, 12345))
		if registered && route && legacyErr == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("peer routes/relay registrations:", ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	legacyStack, err := server.Tun.(*tailnetTun).await()
	if err != nil {
		t.Fatal(err)
	}
	liteStack, err := node.tun.await()
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []struct {
		name     string
		sender   netapi.Proxy
		receiver *wireguard.LightweightNetTun
		target   netip.Addr
	}{
		{"lite-to-tsnet", p, legacyStack, legacyIP}, {"tsnet-to-lite", legacy, liteStack, liteIP},
	} {
		t.Run(direction.name, func(t *testing.T) {
			listener, err := direction.receiver.ListenTCP(net.TCPAddrFromAddrPort(netip.AddrPortFrom(direction.target, 12345)))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				c, err := listener.Accept()
				if err == nil {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					_, _ = io.Copy(c, c)
				}
			}()
			c, err := direction.sender.Conn(ctx, netapi.ParseNetipAddr("tcp", direction.target, 12345))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write([]byte("coexist")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 7)
			if _, err := io.ReadFull(c, reply); err != nil || string(reply) != "coexist" {
				t.Fatal(string(reply), err)
			}
			udp, err := direction.receiver.DialUDP(net.UDPAddrFromAddrPort(netip.AddrPortFrom(direction.target, 12346)), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			go func() {
				buf := make([]byte, 128)
				n, from, err := udp.ReadFrom(buf)
				if err == nil {
					_, _ = udp.WriteTo(buf[:n], from)
				}
			}()
			target := netapi.ParseNetipAddr("udp", direction.target, 12346)
			pc, err := direction.sender.PacketConn(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			if err := pc.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := pc.WriteTo([]byte("coexist"), target); err != nil {
				t.Fatal(err)
			}
			n, _, err := pc.ReadFrom(reply)
			if err != nil || string(reply[:n]) != "coexist" {
				t.Fatal(string(reply[:n]), err)
			}
		})
	}
	assigned := client.Snapshot().Addresses
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := NewLite(cfg, direct.Default)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	renewed, err := replacement.(*Lite).ready(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if control.NumNodes() != 2 || renewed.Snapshot().Addresses[0] != assigned[0] {
		t.Fatal("lite restart re-enrolled identity")
	}
	if legacy.(*Tailscale).NodeRuntimeStatus().State != "configured" {
		t.Fatal("closing lite affected tsnet")
	}
}
