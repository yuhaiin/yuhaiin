//go:build !ts_omit_tailnetlock

package tailscale

import (
	"context"
	"encoding/binary"
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
	wire "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func TestLiteDNSBeforeTransportEcho(t *testing.T) {
	for _, echo := range []bool{false, true} {
		name := "without-self-transport-echo"
		if echo {
			name = "with-self-transport-echo"
		}
		t.Run(name, func(t *testing.T) {
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
			stunAddr, stopSTUN := stuntest.Serve(t)
			defer stopSTUN()
			control := &testcontrol.Server{
				DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {
					RegionID: 1, RegionCode: "local", Nodes: []*tailcfg.DERPNode{{Name: "local", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: port, STUNPort: stunAddr.Port, InsecureForTests: true}},
				}}},
				MagicDNSDomain: "taild2025.ts.net", Logf: logger.Discard,
				DNSConfig: &tailcfg.DNSConfig{Proxied: true, ExtraRecords: []tailcfg.DNSRecord{
					{Name: "5600g.taild2025.ts.net.", Type: "A", Value: "100.64.0.2"},
					{Name: "5600g.taild2025.ts.net.", Type: "AAAA", Value: "fd7a:115c:a1e0::2"},
				}},
			}
			control.ModifyFirstMapResponse = func(m *tailcfg.MapResponse, r *tailcfg.MapRequest) {
				m.Node.Endpoints = nil
				m.Node.HomeDERP = 0
				if echo {
					m.Node.HomeDERP = 1
				}
				// Keep the authorized DNS map, but do not echo later endpoint uploads.
				control.AddRawMapResponse(r.NodeKey, &tailcfg.MapResponse{KeepAlive: true})
			}
			control.HTTPTestServer = httptest.NewServer(control)
			defer control.HTTPTestServer.Close()
			p, err := NewLite(Config{AuthKey: "local-test-key", Hostname: "dns-probe", ControlURL: control.HTTPTestServer.URL}, direct.Default)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			node := p.(*Lite)
			setup, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			c, err := node.init(setup)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.WaitReady(setup); err != nil {
				t.Fatal(err)
			}
			packet := dnsRequest(t, 1, "5600g.taild2025.ts.net.", wire.TypeA)
			response, err := c.QueryDNS(setup, packet, "udp", netip.AddrPort{})
			if err != nil {
				t.Fatal("direct DNS manager:", err)
			}
			var reply wire.Message
			if err := reply.Unpack(response); err != nil || len(reply.Answers) != 1 {
				t.Fatalf("direct DNS response: %+v %v", reply, err)
			}
			service := netapi.ParseNetipAddr("udp", netip.MustParseAddr("100.100.100.100"), 53)
			ctx, stop := context.WithTimeout(t.Context(), time.Second)
			defer stop()
			start := time.Now()
			pc, err := node.PacketConn(ctx, service)
			if err != nil {
				t.Fatalf("dial udp 100.100.100.100:53 after %v: %v", time.Since(start), err)
			}
			defer pc.Close()
			for _, typ := range []wire.Type{wire.TypeA, wire.TypeAAAA} {
				if err := pc.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := pc.WriteTo(dnsRequest(t, uint16(typ), "5600g.taild2025.ts.net.", typ), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("100.100.100.100:53"))); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 4096)
				n, _, err := pc.ReadFrom(buf)
				if err != nil {
					t.Fatal(err)
				}
				var reply wire.Message
				if err := reply.Unpack(buf[:n]); err != nil || len(reply.Answers) != 1 {
					t.Fatalf("DNS %v: %+v %v", typ, reply, err)
				}
			}
			tcpService := netapi.ParseNetipAddr("tcp", netip.MustParseAddr("100.100.100.100"), 53)
			conn, err := node.Conn(ctx, tcpService)
			if err != nil {
				t.Fatal("DNS TCP connection:", err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			packet = dnsRequest(t, 28, "5600g.taild2025.ts.net.", wire.TypeAAAA)
			framed := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
			if _, err := conn.Write(append(framed, packet...)); err != nil {
				t.Fatal(err)
			}
			var size [2]byte
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				t.Fatal(err)
			}
			response = make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(conn, response); err != nil {
				t.Fatal(err)
			}
			if err := reply.Unpack(response); err != nil || len(reply.Answers) != 1 {
				t.Fatalf("TCP DNS response: %+v %v", reply, err)
			}
			t.Logf("adapter A/AAAA succeeded after %v", time.Since(start))
		})
	}
}
