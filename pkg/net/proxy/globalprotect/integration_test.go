package globalprotect

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/tailscale/wireguard-go/tun"
)

// TestGatewayEndToEndTCPUDP starts a full in-process fake HTTPS gateway.
// Unlike the XML fixture tests it drives the public GlobalProtect client
// through prelogin -> login -> config -> TLS tunnel -> gVisor TCP/UDP echo.
// It is NOT a compatibility test against a real PAN-OS server.
func TestGatewayEndToEndTCPUDP(t *testing.T) {
	const (
		serverIP = "10.203.0.1"
		clientIP = "10.203.0.2"
		tcpPort  = 23456
		udpPort  = 23457
		mtu      = 1300
	)
	stack, err := wireguard.CreateNetTUN([]netip.Prefix{netip.MustParsePrefix(serverIP + "/32")}, mtu)
	if err != nil {
		t.Fatal(err)
	}

	tcpListener, err := stack.ListenTCP(&net.TCPAddr{IP: net.ParseIP(serverIP), Port: tcpPort})
	if err != nil {
		_ = stack.Close()
		t.Fatal(err)
	}
	udpSocket, err := stack.DialUDP(&net.UDPAddr{IP: net.ParseIP(serverIP), Port: udpPort}, nil)
	if err != nil {
		_ = tcpListener.Close()
		_ = stack.Close()
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	go func() {
		buf := make([]byte, mtu)
		for {
			n, src, err := udpSocket.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err = udpSocket.WriteTo(buf[:n], src); err != nil {
				return
			}
		}
	}()

	var (
		mu            sync.Mutex
		authenticated bool
		loginCount    int
		sawLogout     bool
		tunnelCount   int
	)
	dropFirstTunnel := make(chan struct{}, 1)
	tunnelReady := make(chan int, 2)
	defer func() {
		select {
		case dropFirstTunnel <- struct{}{}:
		default:
		}
	}()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssl-vpn/prelogin.esp":
			_, _ = io.WriteString(w, "<prelogin-response><status>Success</status><saml-auth-status>0</saml-auth-status></prelogin-response>")
		case "/ssl-vpn/login.esp":
			_ = r.ParseForm()
			if r.Form.Get("user") != "alice" || r.Form.Get("passwd") != "secret" {
				http.Error(w, "bad credentials", http.StatusUnauthorized)
				return
			}
			mu.Lock()
			authenticated = true
			loginCount++
			mu.Unlock()
			_, _ = io.WriteString(w, "<jnlp><application-desc>"+
				"<argument>(null)</argument><argument>test-cookie</argument>"+
				"<argument>unused</argument><argument>test-gateway</argument>"+
				"<argument>alice</argument><argument>LDAP</argument>"+
				"<argument>vsys1</argument><argument>test-domain</argument>"+
				"<argument></argument><argument></argument><argument></argument><argument></argument>"+
				"<argument>tunnel</argument><argument>-1</argument><argument>4100</argument>"+
				"</application-desc></jnlp>")
		case "/ssl-vpn/getconfig.esp":
			_ = r.ParseForm()
			if r.Form.Get("authcookie") != "test-cookie" {
				http.Error(w, "no cookie", http.StatusForbidden)
				return
			}
			_, _ = fmt.Fprintf(w, `<response status="success"><need-tunnel>yes</need-tunnel>
<ip-address>%s</ip-address><netmask>255.255.255.255</netmask>
<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>%d</mtu>
<timeout>3600</timeout><dns></dns><dns-v6></dns-v6><dns-suffix></dns-suffix>
<access-routes><member>192.0.2.100/32</member><member>198.51.100.21/32</member>
<member>203.0.113.5/32</member><member>192.0.2.0/24</member><member>198.51.100.0/24</member>
<member>203.0.113.0/24</member><member>198.18.103.0/24</member></access-routes>
<exclude-access-routes></exclude-access-routes><access-routes-v6></access-routes-v6>
<exclude-access-routes-v6></exclude-access-routes-v6>
<no-direct-access-to-local-network>no</no-direct-access-to-local-network>
<ipsec><ipsec-mode>esp-tunnel</ipsec-mode></ipsec></response>`, clientIP, mtu)
		case "/ssl-vpn/logout.esp":
			mu.Lock()
			sawLogout = true
			mu.Unlock()
			_, _ = io.WriteString(w, "<response status=\"success\"/>")
		case "/ssl-tunnel-connect.sslvpn":
			if r.URL.Query().Get("authcookie") != "test-cookie" {
				http.Error(w, "no cookie", http.StatusForbidden)
				return
			}
			hijack, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijacker", http.StatusInternalServerError)
				return
			}
			conn, _, err := hijack.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			if _, err := io.WriteString(conn, "START_TUNNEL"); err != nil {
				return
			}
			mu.Lock()
			tunnelCount++
			tunnelNumber := tunnelCount
			mu.Unlock()
			tunnelReady <- tunnelNumber
			if tunnelNumber == 1 {
				go func() {
					<-dropFirstTunnel
					_ = conn.Close()
				}()
			}
			var writeMu sync.Mutex
			writeFrame := func(frame []byte) error {
				writeMu.Lock()
				defer writeMu.Unlock()
				_, err := conn.Write(frame)
				return err
			}
			// Drain outgoing packets from the server-side gVisor stack and
			// send them to the client's TLS transport.
			go func() {
				slab := make([]byte, mtu+2*tun.ReadPacketSpacing)
				desc := make([]tun.ReadPacket, 1)
				for {
					n, err := stack.Read(slab, desc)
					if err != nil {
						return
					}
					for _, p := range desc[:n] {
						if p.Offset < 0 || p.Size <= 0 || p.Offset+p.Size > len(slab) {
							return
						}
						frame, err := encodeFrame(slab[p.Offset : p.Offset+p.Size])
						if err != nil || writeFrame(frame) != nil {
							return
						}
					}
				}
			}()
			for {
				packet, dpd, err := readFrame(conn)
				if err != nil {
					return
				}
				if dpd {
					if writeFrame(dpdFrame()) != nil {
						return
					}
					continue
				}
				if _, err := stack.Write([][]byte{packet}, 0); err != nil {
					return
				}
			}
		default:
			http.NotFound(w, r)
		}
	})
	server := httptest.NewTLSServer(handler)
	t.Cleanup(func() {
		server.CloseClientConnections()
		_ = tcpListener.Close()
		_ = udpSocket.Close()
		_ = stack.Close()
		server.Close()
	})
	gateway := strings.TrimPrefix(server.URL, "https://")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	proxy, err := NewClient(Config{
		Gateway: gateway, Username: "alice", Password: "secret",
		CACertPEM: string(ca), MTU: mtu,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	select {
	case tunnelNumber := <-tunnelReady:
		if tunnelNumber != 1 {
			t.Fatalf("initial tunnel number = %d, want 1", tunnelNumber)
		}
	case <-ctx.Done():
		t.Fatal("initial tunnel did not start")
	}
	infoProvider, ok := proxy.(interface {
		NodeExtraInfo() contractnode.NodeExtraInfo
	})
	if !ok {
		t.Fatalf("GlobalProtect proxy does not expose gateway extra info: %T", proxy)
	}
	info := infoProvider.NodeExtraInfo().GlobalProtect
	wantRoutes := []string{
		"192.0.2.100/32", "198.51.100.21/32", "203.0.113.5/32",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.103.0/24",
	}
	if info == nil || info.TunnelPrefix != clientIP+"/32" || !slices.Equal(info.AccessRoutesIPv4, wantRoutes) ||
		len(info.ExcludeRoutesIPv4) != 0 || info.NoDirectAccessToLocalNetwork != "no" {
		t.Fatalf("unexpected gateway extra info: %+v", info)
	}

	tcpAddr, err := netapi.ParseAddress("tcp", fmt.Sprintf("%s:%d", serverIP, tcpPort))
	if err != nil {
		t.Fatal(err)
	}
	tcpConn, err := proxy.Conn(ctx, tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpConn.Close()
	_ = tcpConn.SetDeadline(time.Now().Add(5 * time.Second))
	data := []byte("globalprotect-tcp-e2e")
	if _, err := tcpConn.Write(data); err != nil {
		t.Fatal(err)
	}
	echoed := make([]byte, len(data))
	if _, err := io.ReadFull(tcpConn, echoed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, echoed) {
		t.Fatalf("TCP echo mismatch: %q", echoed)
	}

	udpAddr, err := netapi.ParseAddress("udp", fmt.Sprintf("%s:%d", serverIP, udpPort))
	if err != nil {
		t.Fatal(err)
	}
	packetConn, err := proxy.PacketConn(ctx, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	_ = packetConn.SetDeadline(time.Now().Add(5 * time.Second))
	udpPayload := []byte("globalprotect-udp-e2e")
	if _, err := packetConn.WriteTo(udpPayload, &net.UDPAddr{IP: net.ParseIP(serverIP), Port: udpPort}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, _, err := packetConn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], udpPayload) {
		t.Fatalf("UDP echo mismatch: %q", buf[:n])
	}
	_ = tcpConn.Close()
	_ = packetConn.Close()

	dropFirstTunnel <- struct{}{}
	select {
	case tunnelNumber := <-tunnelReady:
		if tunnelNumber != 2 {
			t.Fatalf("reconnected tunnel number = %d, want 2", tunnelNumber)
		}
	case <-ctx.Done():
		t.Fatal("GlobalProtect client did not reconnect after tunnel loss")
	}
	reconnectedConn, err := proxy.Conn(ctx, tcpAddr)
	if err != nil {
		t.Fatalf("dial after tunnel reconnect: %v", err)
	}
	defer reconnectedConn.Close()
	_ = reconnectedConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := reconnectedConn.Write(data); err != nil {
		t.Fatalf("write after tunnel reconnect: %v", err)
	}
	if _, err := io.ReadFull(reconnectedConn, echoed); err != nil {
		t.Fatalf("read after tunnel reconnect: %v", err)
	}
	if !bytes.Equal(data, echoed) {
		t.Fatalf("TCP echo after reconnect mismatch: %q", echoed)
	}

	mu.Lock()
	wasAuthenticated := authenticated
	logins := loginCount
	mu.Unlock()
	if !wasAuthenticated {
		t.Fatal("gateway authentication was bypassed")
	}
	if logins < 2 {
		t.Fatalf("gateway login count = %d, want at least 2", logins)
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	didLogout := sawLogout
	mu.Unlock()
	if !didLogout {
		t.Fatal("gateway did not receive logout")
	}
	if _, err := proxy.Conn(ctx, tcpAddr); err == nil {
		t.Fatal("closed proxy accepted TCP dial")
	}
}
