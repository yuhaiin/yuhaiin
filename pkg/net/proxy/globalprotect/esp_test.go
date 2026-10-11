package globalprotect

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/tailscale/wireguard-go/tun"
)

func testESPConfig() espConfig {
	key := func(b byte, n int) espKey {
		return espKey{Bits: n * 8, Value: hex.EncodeToString(bytes.Repeat([]byte{b}, n))}
	}
	return espConfig{Mode: "esp-tunnel", Enc: "aes-128-cbc", Auth: "sha256", OutSPI: "0x1001", InSPI: "0x1002", OutKey: key(1, 16), InKey: key(2, 16), OutMAC: key(3, 32), InMAC: key(4, 32)}
}
func reverseESPConfig(c espConfig) espConfig {
	c.OutSPI, c.InSPI = c.InSPI, c.OutSPI
	c.OutKey, c.InKey = c.InKey, c.OutKey
	c.OutMAC, c.InMAC = c.InMAC, c.OutMAC
	return c
}
func TestESPAuthenticatedReplayWindow(t *testing.T) {
	cfg := testESPConfig()
	out, err := newESPSA(cfg)
	if err != nil {
		t.Fatal(err)
	}
	in, err := newESPSA(reverseESPConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	ip := activationPing(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"), 1)
	packet, err := out.seal(ip)
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.Clone(packet)
	forged[4] = 0xff
	if _, err := in.open(forged); err == nil {
		t.Fatal("tampered sequence accepted")
	}
	forged = bytes.Clone(packet)
	forged[26] ^= 1
	if _, err := in.open(forged); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	got, err := in.open(bytes.Clone(packet))
	if err != nil || !bytes.Equal(got, ip) {
		t.Fatalf("authenticated packet rejected: %v", err)
	}
	if _, err := in.open(bytes.Clone(packet)); err == nil {
		t.Fatal("replay accepted")
	}
	out.seq = 0xffffffff
	if _, err := out.seal(ip); err == nil {
		t.Fatal("sequence wrap accepted")
	}
	for _, change := range []func(*espConfig){
		func(c *espConfig) { c.Enc = "aes-256-gcm" }, func(c *espConfig) { c.Auth = "md5" },
		func(c *espConfig) { c.OutKey.Bits = 256 }, func(c *espConfig) { c.InSPI = "0" },
	} {
		c := cfg
		change(&c)
		if _, err := newESPSA(c); err == nil {
			t.Fatal("invalid SA accepted")
		}
	}
}

// This simulator verifies encrypted transport selection and gVisor egress.
// It is not a PAN-OS interoperability claim.
func TestGatewayESPAndSSLFallback(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(fmt.Sprintf("blocked=%v", blocked), func(t *testing.T) { testESPGateway(t, blocked) })
	}
}
func testESPGateway(t *testing.T, blocked bool) {
	cfg := testESPConfig()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	cfg.Port = socket.LocalAddr().(*net.UDPAddr).Port
	serverSA, err := newESPSA(reverseESPConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	stack, err := wireguard.CreateNetTUN([]netip.Prefix{netip.MustParsePrefix("10.204.0.1/32")}, 1300)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.Close()
	listener, err := stack.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.204.0.1"), Port: 23456})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	udp, err := stack.DialUDP(&net.UDPAddr{IP: net.ParseIP("10.204.0.1"), Port: 23457}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], peer)
		}
	}()
	var mu sync.Mutex
	var peer *net.UDPAddr
	var tlsOpened bool
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := socket.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if blocked {
				continue
			}
			ip, err := serverSA.open(buf[:n])
			if err != nil {
				continue
			}
			mu.Lock()
			peer = addr
			mu.Unlock()
			if isActivationPacket(ip) {
				packet, err := serverSA.seal(ip)
				if err == nil {
					_, _ = socket.WriteToUDP(packet, addr)
				}
				continue
			}
			_, _ = stack.Write([][]byte{ip}, 0)
		}
	}()
	if !blocked {
		go func() {
			buf := make([]byte, 1300+2*tun.ReadPacketSpacing)
			desc := make([]tun.ReadPacket, 1)
			for {
				n, err := stack.Read(buf, desc)
				if err != nil {
					return
				}
				for _, p := range desc[:n] {
					packet, err := serverSA.seal(buf[p.Offset : p.Offset+p.Size])
					if err != nil {
						return
					}
					mu.Lock()
					addr := peer
					mu.Unlock()
					if addr != nil {
						_, _ = socket.WriteToUDP(packet, addr)
					}
				}
			}
		}()
	}
	encoded, err := xml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	espXML := strings.ReplaceAll(strings.ReplaceAll(string(encoded), "espConfig>", "ipsec>"), "<espConfig", "<ipsec")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ssl-vpn/prelogin.esp":
			_, _ = io.WriteString(w, "<prelogin-response><status>Success</status><saml-auth-status>0</saml-auth-status></prelogin-response>")
		case "/ssl-vpn/login.esp":
			args := make([]string, 16)
			args[1] = "cookie"
			args[3] = "gateway"
			args[4] = "alice"
			args[12] = "tunnel"
			args[14] = "4100"
			_, _ = io.WriteString(w, "<jnlp><application-desc>")
			for _, arg := range args {
				_, _ = fmt.Fprintf(w, "<argument>%s</argument>", arg)
			}
			_, _ = io.WriteString(w, "</application-desc></jnlp>")
		case "/ssl-vpn/getconfig.esp":
			_ = r.ParseForm()
			if r.Form.Get("hmac-algo") != "sha256,sha1" {
				t.Error("unsupported HMAC advertised")
			}
			_, _ = fmt.Fprintf(w, "<response><ip-address>10.204.0.2</ip-address><netmask>255.255.255.255</netmask><gw-address>127.0.0.1</gw-address><mtu>1300</mtu>%s</response>", espXML)
		case "/ssl-tunnel-connect.sslvpn":
			mu.Lock()
			tlsOpened = true
			mu.Unlock()
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = io.WriteString(conn, "START_TUNNEL")
			for {
				_, dpd, err := readFrame(conn)
				if err != nil {
					return
				}
				if dpd {
					_, _ = conn.Write(dpdFrame())
				}
			}
		case "/ssl-vpn/logout.esp":
			_, _ = io.WriteString(w, "<response status=\"success\"/>")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	defer server.CloseClientConnections()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	proxy, err := NewClient(Config{Gateway: strings.TrimPrefix(server.URL, "https://"), Username: "alice", Password: "secret", CACertPEM: string(ca), UseESP: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	info := proxy.(interface {
		NodeExtraInfo() contractnode.NodeExtraInfo
	}).NodeExtraInfo().GlobalProtect
	mu.Lock()
	opened := tlsOpened
	mu.Unlock()
	if blocked {
		if !opened || info.DataTransport != "ssl" {
			t.Fatal("blocked UDP did not fall back to SSL")
		}
		return
	}
	if opened || info.DataTransport != "esp" {
		t.Fatal("usable ESP opened SSL tunnel")
	}
	ctx := t.Context()
	tcpAddr, _ := netapi.ParseAddress("tcp", "10.204.0.1:23456")
	conn, err := proxy.Conn(ctx, tcpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("TCP through authenticated ESP")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("bad TCP echo")
	}
	udpAddr, _ := netapi.ParseAddress("udp", "10.204.0.1:23457")
	packet, err := proxy.PacketConn(ctx, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	if err := packet.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.WriteTo(payload, udpAddr); err != nil {
		t.Fatal(err)
	}
	n, _, err := packet.ReadFrom(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], payload) {
		t.Fatal("bad UDP echo")
	}
}

func TestGlobalProtectHonorsUpstreamFailure(t *testing.T) {
	refused := errors.New("upstream refused connection")
	p, err := NewClient(Config{Gateway: "127.0.0.1:443", Username: "alice", Password: "secret", UseESP: true}, netapi.NewErrProxy(refused))
	if p != nil {
		_ = p.Close()
		t.Fatal("connected despite upstream refusal")
	}
	if !errors.Is(err, refused) {
		t.Fatalf("upstream error lost or bypassed: %v", err)
	}
}
