//go:build !ts_omit_tailnetlock

package tailscale

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	lite "github.com/yuhaiin/tailscale-lite"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// Two nodes use the host's actual lightweight stack and custom per-node
// underlays, not fake packet devices or an OS TUN.
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
	// Real DNS forwarder on localhost; the embedded Tailscale DNS manager
	// must select this resolver from the control-supplied split/default
	// policy, then send UDP through this node's injected Underlay.
	dnsUpstream, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsUpstream.Close()
	var peerDNSAddress netip.Addr
	peerDNSReady := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := dnsUpstream.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dns.Msg
			q.Data = buf[:n]
			if q.Unpack() != nil || len(q.Question) != 1 {
				continue
			}
			question := netapi.DNSQuestionFromRR(q.Question[0])
			response := netapi.NewDNSMsg(question)
			response.ID = q.ID
			response.Response = true
			response.RecursionAvailable = true
			var answerIP netip.Addr
			switch question.Name {
			case "lookup.corp.example.":
				answerIP = netip.MustParseAddr("192.0.2.31")
			case "ordinary.example.":
				answerIP = netip.MustParseAddr("192.0.2.41")
			case "peer.corp.example.":
				select {
				case <-peerDNSReady:
					answerIP = peerDNSAddress
				default:
					continue
				}
			default:
				continue
			}
			if question.Qtype == dns.TypeA {
				response.Answer = append(response.Answer, &dns.A{
					Hdr:  dns.Header{Name: question.Name, Class: dns.ClassINET, TTL: 30},
					Addr: answerIP,
				})
			}
			if response.Pack() == nil {
				_, _ = dnsUpstream.WriteTo(response.Data, from)
			}
		}
	}()
	control := &testcontrol.Server{
		DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {
			RegionID: 1, RegionCode: "local",
			Nodes: []*tailcfg.DERPNode{{Name: "local", RegionID: 1, HostName: "127.0.0.1",
				IPv4: "127.0.0.1", IPv6: "none", DERPPort: port, STUNPort: -1, InsecureForTests: true}},
		}}},
		DNSConfig: &tailcfg.DNSConfig{
			Proxied:   true,
			Resolvers: []*dnstype.Resolver{{Addr: dnsUpstream.LocalAddr().String()}},
			Routes: map[string][]*dnstype.Resolver{
				"corp.example": {{Addr: dnsUpstream.LocalAddr().String()}},
			},
		},
		MagicDNSDomain: "tail-scale.ts.net",
		Logf:           logger.Discard,
	}
	control.HTTPTestServer = httptest.NewServer(control)
	defer control.HTTPTestServer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 55*time.Second)
	defer cancel()

	var nodes [2]*Tailscale
	var clients [2]*lite.Client
	var proxies [2]*recordingProxy
	for i := range nodes {
		proxies[i] = &recordingProxy{Proxy: direct.Default}
		p, err := New(Config{AuthKey: "local-test-key", Hostname: fmt.Sprintf("adapter%d", i),
			ControlURL: control.HTTPTestServer.URL}, proxies[i])
		if err != nil {
			t.Fatal(err)
		}
		nodes[i] = p.(*Tailscale)
		defer nodes[i].Close()
	}
	var wg sync.WaitGroup
	for i := range nodes {
		wg.Go(func() {
			cl, err := nodes[i].ready(ctx)
			if err != nil {
				t.Errorf("node %d: %v", i, err)
				return
			}
			clients[i] = cl
		})
	}
	wg.Wait()
	if t.Failed() {
		return
	}
	ip4 := func(c *lite.Client) netip.Addr {
		for _, p := range c.Snapshot().Addresses {
			if p.Addr().Is4() {
				return p.Addr()
			}
		}
		return netip.Addr{}
	}
	target := ip4(clients[1])
	if !target.IsValid() {
		t.Fatal("peer missing IPv4 Tailnet address")
	}
	peerDNSAddress = target
	close(peerDNSReady)
	for {
		if _, ok := clients[0].Route(target); ok {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("peer route did not arrive", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	peerName := netapi.ParseNetipAddr("tcp", target, 12345)
	dnsName, err := netapi.ParseAddress("tcp", "adapter1.tail-scale.ts.net.:12345")
	if err != nil {
		t.Fatal(err)
	}
	peerByName, err := resolveAddr(ctx, clients[0], "tcp", dnsName)
	if err != nil || peerByName.Addr() != target {
		t.Fatalf("MagicDNS: %v %v", peerByName, err)
	}

	stack, err := nodes[1].tun.await()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("tcp-encrypted-lightweight", func(t *testing.T) {
		ln, err := stack.ListenTCP(&net.TCPAddr{IP: net.IP(target.AsSlice()), Port: 12345})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			c, err := ln.Accept()
			if err == nil {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(8 * time.Second))
				_, _ = io.Copy(c, c)
			}
		}()
		c, err := nodes[0].Conn(ctx, peerName)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(8 * time.Second))
		want := []byte("lightweight over encrypted Tailnet")
		if _, err = c.Write(want); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
			t.Fatalf("TCP echo: %q %v", got, err)
		}
	})
	t.Run("udp-encrypted-lightweight", func(t *testing.T) {
		remote := netip.AddrPortFrom(target, 12346)
		server, err := stack.DialUDP(net.UDPAddrFromAddrPort(remote), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		go func() {
			buf := make([]byte, 512)
			n, from, err := server.ReadFrom(buf)
			if err == nil {
				_, _ = server.WriteTo(buf[:n], from)
			}
		}()
		client, err := nodes[0].PacketConn(ctx, netapi.ParseNetipAddr("udp", target, 12346))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		_ = client.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err = client.WriteTo([]byte("test-udp"), net.UDPAddrFromAddrPort(remote)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 256)
		n, from, err := client.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "test-udp" || from.String() != remote.String() {
			t.Fatalf("UDP echo: %q %v %v", buf[:n], from, err)
		}
	})
	t.Run("magic-dns", func(t *testing.T) {
		request := netapi.NewDNSMsg(netapi.DNSQuestion{
			Name: "adapter1.tail-scale.ts.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		})
		request.Response = false
		request.ID = 0x7161
		if err := request.Pack(); err != nil {
			t.Fatal(err)
		}
		wire := request.Data
		service := netapi.ParseNetipAddr("udp", netip.MustParseAddr("100.100.100.100"), 53)
		p, err := nodes[0].PacketConn(ctx, service)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		_ = p.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err = p.WriteTo(wire, service); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		n, _, err := p.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		var answer dns.Msg
		answer.Data = buf[:n]
		if err = answer.Unpack(); err != nil {
			t.Fatal(err)
		}
		if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
			t.Fatalf("DNS response %+v", &answer)
		}
	})
	// Verify DNS query transport compatibility through the actual adapter,
	// not a test-only fake DNS Manager.
	askDNS := func(t *testing.T, question string, qtype uint16) dns.Msg {
		t.Helper()
		request := netapi.NewDNSMsg(netapi.DNSQuestion{
			Name: question, Qtype: qtype, Qclass: dns.ClassINET,
		})
		request.Response = false
		request.ID = 0x6622
		if err := request.Pack(); err != nil {
			t.Fatal(err)
		}
		server := netapi.ParseNetipAddr("udp", netip.MustParseAddr("100.100.100.100"), 53)
		pc, err := nodes[0].PacketConn(ctx, server)
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		_ = pc.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err := pc.WriteTo(request.Data, server); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		var answer dns.Msg
		answer.Data = buf[:n]
		if err := answer.Unpack(); err != nil {
			t.Fatal(err)
		}
		if answer.ID != request.ID {
			t.Fatalf("DNS ID changed %v -> %v", request.ID, answer.ID)
		}
		return answer
	}
	t.Run("split-dns-via-underlay", func(t *testing.T) {
		answer := askDNS(t, "lookup.corp.example.", dns.TypeA)
		if len(answer.Answer) != 1 || answer.Answer[0].(*dns.A).Addr.String() != "192.0.2.31" {
			t.Fatalf("split DNS not routed by control policy: %+v", &answer)
		}
	})
	t.Run("split-dns-connect-to-tailnet-peer", func(t *testing.T) {
		name, err := netapi.ParseAddress("tcp", "peer.corp.example:12345")
		if err != nil {
			t.Fatal(err)
		}
		got, err := resolveAddr(ctx, clients[0], "tcp", name)
		if err != nil || got.Addr() != target {
			t.Fatalf("Split DNS peer resolved to %s, error=%v", got, err)
		}
	})
	t.Run("default-dns-via-underlay", func(t *testing.T) {
		answer := askDNS(t, "ordinary.example.", dns.TypeA)
		if len(answer.Answer) != 1 || answer.Answer[0].(*dns.A).Addr.String() != "192.0.2.41" {
			t.Fatalf("default DNS not routed by control policy: %+v", &answer)
		}
	})
	t.Run("reverse-ptr", func(t *testing.T) {
		octets := target.As4()
		name := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", octets[3], octets[2], octets[1], octets[0])
		answer := askDNS(t, name, dns.TypePTR)
		if answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
			t.Fatalf("peer PTR not synthesized: %+v", &answer)
		}
	})
	t.Run("dns-tcp", func(t *testing.T) {
		server := netapi.ParseNetipAddr("tcp", netip.MustParseAddr("100.100.100.100"), 53)
		stream, err := nodes[0].Conn(ctx, server)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(8 * time.Second))
		request := netapi.NewDNSMsg(netapi.DNSQuestion{
			Name: "adapter1.tail-scale.ts.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET,
		})
		request.Response = false
		request.ID = 0x6623
		if err := request.Pack(); err != nil {
			t.Fatal(err)
		}
		var header [2]byte
		binary.BigEndian.PutUint16(header[:], uint16(len(request.Data)))
		if _, err := stream.Write(append(header[:], request.Data...)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(stream, header[:]); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, err := io.ReadFull(stream, buf); err != nil {
			t.Fatal(err)
		}
		var answer dns.Msg
		answer.Data = buf
		if err := answer.Unpack(); err != nil {
			t.Fatal(err)
		}
		if answer.ID != request.ID || len(answer.Answer) != 1 {
			t.Fatalf("DNS TCP manager failed: %+v", &answer)
		}
	})
	t.Run("forbid-system-fallback", func(t *testing.T) {
		if _, err := nodes[0].Conn(ctx, netapi.ParseNetipAddr("tcp", netip.MustParseAddr("127.0.0.1"), 9)); err == nil {
			t.Fatal("system TCP fallback escaped")
		}
	})
	for _, p := range proxies {
		p.mu.Lock()
		tcp, udp := p.tcp, p.udp
		p.mu.Unlock()
		if tcp == 0 || udp == 0 {
			t.Fatalf("per-instance Underlay bypass tcp=%d udp=%d", tcp, udp)
		}
	}
}
