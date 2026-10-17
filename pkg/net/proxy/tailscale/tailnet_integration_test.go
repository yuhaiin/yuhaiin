//go:build !ts_omit_tailnetlock

package tailscale

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	wire "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// Exercises this adapter against local Tailscale control/DERP services and
// real WireGuard/netstack traffic, without production keys or a real account.
func TestLocalTailnet(t *testing.T) {
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
	control := &testcontrol.Server{
		DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {
			RegionID: 1, RegionCode: "local", Nodes: []*tailcfg.DERPNode{{Name: "local", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: port, STUNPort: -1, InsecureForTests: true}},
		}}},
		DNSConfig: &tailcfg.DNSConfig{Proxied: true}, MagicDNSDomain: "tail-scale.ts.net", Logf: logger.Discard,
	}
	control.HTTPTestServer = httptest.NewServer(control)
	defer control.HTTPTestServer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var nodes [2]*Tailscale
	var servers [2]*tsnet.Server
	var proxies [2]*recordingProxy
	for i := range nodes {
		proxies[i] = &recordingProxy{Proxy: direct.Default}
		p, err := New(Config{AuthKey: "local-test-key", Hostname: fmt.Sprintf("adapter%d", i), ControlURL: control.HTTPTestServer.URL}, proxies[i])
		if err != nil {
			t.Fatal(err)
		}
		nodes[i] = p.(*Tailscale)
		defer p.Close()
	}
	var wg sync.WaitGroup
	for i := range nodes {
		wg.Go(func() {
			s, err := nodes[i].ready(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			servers[i] = s
		})
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	for _, s := range servers {
		if s.AuthKey != "" {
			t.Fatal("started network server retained its bootstrap authentication key")
		}
	}
	a, b := nodes[0], nodes[1]
	target, err := netapi.ParseAddress("tcp", "ADAPTER1.tail-scale.ts.net.:12345")
	if err != nil {
		t.Fatal(err)
	}
	// Wait for the peer's route to arrive after the initial Up result.
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := resolveAddr(ctx, servers[0], "tcp", target)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Run("tcp", func(t *testing.T) {
		ln, err := servers[1].Listen("tcp", ":12345")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err == nil {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(c, c)
			}
		}()
		c, err := a.Conn(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, ok := c.(*lightweight.TCPConn); !ok {
			t.Fatalf("outbound TCP uses %T, want lightweight", c)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
			t.Fatalf("%q %v", buf, err)
		}
	})
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ip, _ := servers[1].TailscaleIPs()
			if network == "udp6" {
				_, ip = servers[1].TailscaleIPs()
			}
			if !ip.IsValid() {
				t.Fatal("missing test address family")
			}
			dst := netapi.ParseNetipAddr(network, ip, 12345)
			pc, err := a.PacketConn(ctx, dst)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			if _, ok := pc.(*tailnetPacketConn).PacketConn.(*lightweight.UDPConn); !ok {
				t.Fatal("outbound UDP does not use lightweight")
			}
			_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
			// The same PacketConn must deliver to distinct destination ports correctly.
			for _, port := range []uint16{12345, 12346} {
				remote := netip.AddrPortFrom(ip, port)
				listener, err := servers[1].ListenPacket(network, remote.String())
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				go func() {
					buf := make([]byte, 32)
					n, from, err := listener.ReadFrom(buf)
					if err == nil {
						_, _ = listener.WriteTo(buf[:n], from)
					}
				}()
				if _, err := pc.WriteTo([]byte("hello"), net.UDPAddrFromAddrPort(remote)); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, 32)
				n, from, err := pc.ReadFrom(buf)
				if err != nil || string(buf[:n]) != "hello" || from.String() != remote.String() {
					t.Fatalf("%q %v %v", buf[:n], from, err)
				}
			}
			if _, err := pc.WriteTo([]byte("blocked"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err == nil {
				t.Fatal("non-tailnet UDP escaped")
			}
		})
	}
	t.Run("metrics-lightweight-listener", func(t *testing.T) {
		old := Mux.Load()
		mux := http.NewServeMux()
		mux.HandleFunc("GET /stack-test", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "lightweight metrics") })
		Mux.Store(mux)
		defer Mux.Store(old)
		ip, _ := servers[1].TailscaleIPs()
		conn, err := a.Conn(ctx, netapi.ParseNetipAddr("tcp", ip, 80))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, "GET /stack-test HTTP/1.1\r\nHost: tailnet\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || string(body) != "lightweight metrics" {
			t.Fatalf("metrics: %q %v", body, err)
		}
	})

	t.Run("route_rejection", func(t *testing.T) {
		_, err := a.Conn(ctx, netapi.ParseNetipAddr("tcp", netip.MustParseAddr("127.0.0.1"), 9))
		if err == nil {
			t.Fatal("non-tailnet TCP escaped")
		}
	})
	t.Run("service_dns", func(t *testing.T) {
		req := dnsRequest(t, 0x9876, "ADAPTER1.tail-scale.ts.net.", wire.TypeA)
		service := netapi.ParseNetipAddr("udp", netip.MustParseAddr("100.100.100.100"), 53)
		pc, err := a.PacketConn(ctx, service)
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := pc.WriteTo(req, service); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		var response wire.Message
		if err := response.Unpack(buf[:n]); err != nil {
			t.Fatal(err)
		}
		if response.ID != 0x9876 || len(response.Answers) != 1 {
			t.Fatalf("UDP DNS: %+v", response)
		}
		c, err := a.Conn(ctx, service)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(req)))
		framed = append(framed, req...)
		if _, err := c.Write(framed); err != nil {
			t.Fatal(err)
		}
		var header [2]byte
		if _, err := io.ReadFull(c, header[:]); err != nil {
			t.Fatal(err)
		}
		buf = make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatal(err)
		}
		if err := response.Unpack(buf); err != nil {
			t.Fatal(err)
		}
		if response.ID != 0x9876 || len(response.Answers) != 1 {
			t.Fatalf("TCP DNS: %+v", response)
		}
	})
	replacementProxy, err := New(a.config, &recordingProxy{Proxy: direct.Default})
	if err != nil {
		t.Fatal(err)
	}
	replacement := replacementProxy.(*Tailscale)
	defer replacement.Close()
	if _, err := replacement.init(ctx); err == nil {
		t.Fatal("live instances shared a state directory")
	}
	// Rebinding one node must preserve its upstream and leave the other alive.
	servers[0].Sys().MagicSock.Get().Rebind()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.ready(ctx); err != nil {
		t.Fatalf("configuration replacement: %v", err)
	}
	if _, err := a.init(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed node restarted: %v", err)
	}
	if _, err := b.ready(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range proxies {
		p.mu.Lock()
		tcp, udp := p.tcp, p.udp
		p.mu.Unlock()
		if tcp == 0 || udp == 0 {
			t.Fatalf("underlay bypassed: tcp=%d udp=%d", tcp, udp)
		}
	}
}
