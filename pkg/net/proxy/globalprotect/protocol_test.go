package globalprotect

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestSSLFrameRoundTrip(t *testing.T) {
	for _, v := range []byte{4, 6} {
		t.Run(string(rune('0'+v)), func(t *testing.T) {
			pkt := make([]byte, 120)
			pkt[0] = v << 4
			frame, err := encodeFrame(pkt)
			if err != nil {
				t.Fatal(err)
			}
			if got := binary.BigEndian.Uint16(frame[6:8]); int(got) != len(pkt) {
				t.Fatalf("length=%d", got)
			}
			decoded, dpd, err := readFrame(bytes.NewReader(frame))
			if err != nil || dpd || !bytes.Equal(decoded, pkt) {
				t.Fatalf("decoded=%v dpd=%t err=%v", decoded, dpd, err)
			}
		})
	}
}

func TestSSLFrameRejectsMalformedInput(t *testing.T) {
	base, err := encodeFrame(append([]byte{0x45}, make([]byte, 50)...))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func([]byte) []byte{
		"magic":        func(b []byte) []byte { b[0] = 0; return b },
		"ethertype":    func(b []byte) []byte { b[4] = 0x86; b[5] = 0xdd; return b },
		"oversize":     func(b []byte) []byte { b[6] = 0x20; return b },
		"short-body":   func(b []byte) []byte { return b[:20] },
		"short-header": func(b []byte) []byte { return b[:8] },
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			b := corrupt(bytes.Clone(base))
			if _, _, err := readFrame(bytes.NewReader(b)); err == nil {
				t.Fatal("accepted invalid frame")
			}
		})
	}
	if _, err := encodeFrame([]byte{0x30}); err == nil {
		t.Fatal("accepted non-IP payload")
	}
	if _, err := encodeFrame(make([]byte, 65536)); err == nil {
		t.Fatal("accepted oversized payload")
	}
}

func TestDPDFrame(t *testing.T) {
	pkt, dpd, err := readFrame(bytes.NewReader(dpdFrame()))
	if err != nil || !dpd || pkt != nil {
		t.Fatalf("packet=%v dpd=%v err=%v", pkt, dpd, err)
	}
	bad := append(dpdFrame(), 0)
	bad[7] = 1
	bad[9] = 1
	if _, dpd, err := readFrame(bytes.NewReader(bad)); err != nil || !dpd {
		t.Fatalf("rejected non-canonical DPD frame: dpd=%t err=%v", dpd, err)
	}
}

func TestDPDResponseTimeout(t *testing.T) {
	now := time.Unix(100, 0)
	for _, test := range []struct {
		age  time.Duration
		want bool
	}{
		{age: globalprotectDPDTimeout - time.Second, want: false},
		{age: globalprotectDPDTimeout, want: true},
		{age: globalprotectDPDTimeout + time.Second, want: true},
	} {
		if got := dpdResponseTimedOut(now, now.Add(-test.age)); got != test.want {
			t.Errorf("DPD timeout at age %s = %t, want %t", test.age, got, test.want)
		}
	}
}

func TestGatewayValidation(t *testing.T) {
	for _, raw := range []string{"http://host", "https://user:pass@host", "https://host/ssl-vpn", "https://host?x=y", ""} {
		if _, err := parseGateway(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"vpn.example.com", "https://vpn.example.com:8443", "127.0.0.1:443"} {
		if _, err := parseGateway(raw); err != nil {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

func TestTLSInsecureSkipVerifyOption(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	for _, skipVerify := range []bool{false, true} {
		name := "verify_certificate"
		if skipVerify {
			name = "skip_verification"
		}
		t.Run(name, func(t *testing.T) {
			c, err := newControl(Config{Gateway: "untrusted.example.invalid", InsecureSkipVerify: skipVerify})
			if err != nil {
				t.Fatal(err)
			}
			defer c.close()
			c.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}

			resp, err := c.client.Get(server.URL)
			if skipVerify {
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				return
			}
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("accepted a self-signed certificate by default")
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestGatewayAuthAndConfig(t *testing.T) {
	c, err := newControl(Config{Gateway: "https://vpn.example.com", Computer: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	steps := []string{"prelogin.esp", "login.esp", "getconfig.esp"}
	index := 0
	c.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if index >= len(steps) || !strings.HasSuffix(r.URL.Path, steps[index]) {
			t.Errorf("unexpected request: %s", r.URL)
		}
		index++
		if r.Header.Get("User-Agent") != "PAN GlobalProtect" {
			t.Error("missing User-Agent")
		}
		var body string
		switch index {
		case 1:
			if r.URL.Query().Get("clientVer") != "4100" {
				t.Errorf("missing prelogin URL query: %s", r.URL)
			}
			body = "<prelogin-response><status>Success</status><saml-auth-status>0</saml-auth-status></prelogin-response>"
		case 2:
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("passwd") != "secret" || r.Form.Get("user") != "alice" {
				t.Error("login form mismatch")
			}
			if r.Form.Get("ipv6-support") != "no" {
				t.Error("login did not disable unsupported IPv6")
			}
			body = "<jnlp><application-desc><argument>(null)</argument><argument>cookie-123</argument><argument></argument><argument>GW</argument><argument>alice</argument><argument>LDAP</argument><argument>vsys1</argument><argument>example</argument><argument></argument><argument></argument><argument></argument><argument></argument><argument>tunnel</argument><argument>-1</argument><argument>4100</argument></application-desc></jnlp>"
		case 3:
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("authcookie") != "cookie-123" {
				t.Error("missing session cookie")
			}
			body = `<response status="success"><need-tunnel>yes</need-tunnel>
<ip-address>10.0.0.8</ip-address><netmask>255.255.255.255</netmask>
<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url><mtu>0</mtu><timeout>3600</timeout>
<dns></dns><dns-v6></dns-v6><dns-suffix></dns-suffix>
<access-routes>
<member>192.0.2.100/32</member><member>198.51.100.21/32</member><member>203.0.113.5/32</member>
<member>192.0.2.0/24</member><member>198.51.100.0/24</member><member>203.0.113.0/24</member><member>198.18.103.0/24</member>
</access-routes>
<exclude-access-routes></exclude-access-routes>
<access-routes-v6></access-routes-v6><exclude-access-routes-v6></exclude-access-routes-v6>
<no-direct-access-to-local-network>no</no-direct-access-to-local-network></response>`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
	})
	ctx := context.Background()
	if err := c.prelogin(ctx); err != nil {
		t.Fatal(err)
	}
	sess, err := c.login(ctx, "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	cfg, ip, err := c.getConfig(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	wantRoutes := []string{
		"192.0.2.100/32", "198.51.100.21/32", "203.0.113.5/32",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.103.0/24",
	}
	if ip.String() != "10.0.0.8/32" || cfg.Timeout != 3600 || index != 3 ||
		!slices.Equal(cfg.AccessRoutes, wantRoutes) || len(cfg.ExcludeRoutes) != 0 ||
		len(cfg.AccessRoutesV6) != 0 || len(cfg.ExcludeRoutesV6) != 0 ||
		cfg.NoDirectAccess != "no" {
		t.Fatalf("ip=%s cfg=%+v requests=%d", ip, cfg, index)
	}
}

func TestNodeExtraInfoCopiesGatewayConfig(t *testing.T) {
	client := Client{extraInfo: contractnode.GlobalProtectInfo{
		TunnelPrefix:     "10.0.0.8/32",
		AccessRoutesIPv4: []string{"192.0.2.0/24"},
	}}
	info := client.NodeExtraInfo()
	if info.GlobalProtect == nil || info.GlobalProtect.TunnelPrefix != "10.0.0.8/32" ||
		!slices.Equal(info.GlobalProtect.AccessRoutesIPv4, []string{"192.0.2.0/24"}) {
		t.Fatalf("unexpected GlobalProtect extra info: %+v", info)
	}
	info.GlobalProtect.AccessRoutesIPv4[0] = "203.0.113.0/24"
	if got := client.NodeExtraInfo().GlobalProtect.AccessRoutesIPv4[0]; got != "192.0.2.0/24" {
		t.Fatalf("returned route slice aliases client state: %s", got)
	}
}

func TestUnsupportedSAML(t *testing.T) {
	c, err := newControl(Config{Gateway: "vpn.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	c.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("<prelogin-response><status>Success</status><saml-auth-status>1</saml-auth-status><saml-request>AAA=</saml-request></prelogin-response>")), Header: http.Header{}, Request: r}, nil
	})
	if err := c.prelogin(context.Background()); !errors.Is(err, ErrInteractiveAuth) {
		t.Fatalf("expected interactive auth error, got %v", err)
	}
}

func TestSSLConnectHandshake(t *testing.T) {
	received := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ssl-tunnel-connect.sslvpn" || r.URL.Query().Get("authcookie") != "cookie123" {
			t.Errorf("bad tunnel request %s", r.URL)
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("no HTTP hijacker")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "START_TUNNEL"); err != nil {
			t.Error(err)
			return
		}
		pkt := append([]byte{0x45}, make([]byte, 31)...)
		frame, _ := encodeFrame(pkt)
		if _, err := conn.Write(frame); err != nil {
			t.Error(err)
			return
		}
		var dpd [frameHeaderSize]byte
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, dpd[:]); err != nil {
			t.Error(err)
			return
		}
		if !bytes.Equal(dpd[:], dpdFrame()) {
			t.Error("expected DPD packet")
		}
		received <- "ok"
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c, err := newControl(Config{Gateway: u.Host})
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	c.tlsConfig.RootCAs = roots
	c.dial = func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", u.Host)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := connectTunnel(ctx, c, session{User: "alice", Cookie: "cookie123"}, "/ssl-tunnel-connect.sslvpn")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	packet, dpd, err := readFrame(conn)
	if err != nil || dpd || packet[0] != 0x45 {
		t.Fatalf("packet=%v dpd=%v err=%v", packet, dpd, err)
	}
	if _, err := conn.Write(dpdFrame()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestInvalidTrustedCA(t *testing.T) {
	if _, err := newControl(Config{Gateway: "example.com", CACertPEM: "garbage"}); err == nil {
		t.Fatal("accepted invalid CA")
	}
	_ = pem.Block{} // keeps PEM test helpers available for certificate follow-up
}

func TestLoginUnauthorizedIsAuthenticationRejected(t *testing.T) {
	c, err := newControl(Config{Gateway: "vpn.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	c.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader("unauthorized")),
			Header:     http.Header{},
			Request:    r,
		}, nil
	})
	if _, err := c.login(context.Background(), "alice", "wrong"); !errors.Is(err, errAuthenticationRejected) {
		t.Fatalf("login error = %v, want authentication rejection", err)
	}
}
