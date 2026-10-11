package globalprotect

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// These cases are independently implemented from publicly documented wire
// behavior and the scenarios in OpenConnect tests/gp-auth-and-config and
// tests/fake-gp-server.py. No upstream source or fixtures are copied.
//
// OpenConnect's fake gateway uses a <response> without status or need-tunnel,
// and checks the JNLP cookie, portal, domain and preferred-ip passed into
// getconfig. The two tests intentionally verify those compatibility details.
func TestOpenConnectGatewayConfigCompatibility(t *testing.T) {
	c, err := newControl(Config{Gateway: "vpn.example.com", Computer: "compat-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	calls := 0
	c.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		var content string
		switch calls {
		case 1:
			if r.URL.Path != "/ssl-vpn/prelogin.esp" {
				t.Errorf("prelogin path=%s", r.URL.Path)
			}
			content = "<prelogin-response><status>Success</status><username-label>User</username-label><password-label>Password</password-label></prelogin-response>"
		case 2:
			if r.URL.Path != "/ssl-vpn/login.esp" {
				t.Errorf("login path=%s", r.URL.Path)
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			for key, want := range map[string]string{
				"user": "alice", "passwd": "pw", "clientVer": "4100", "jnlpReady": "jnlpReady",
				"ok": "Login", "direct": "yes", "computer": "compat-test", "ipv6-support": "no",
			} {
				if got := r.Form.Get(key); got != want {
					t.Errorf("login %s=%q want %q", key, got, want)
				}
			}
			content = "<jnlp><application-desc>" +
				"<argument>(null)</argument><argument>cookie-value</argument><argument>persistent</argument>" +
				"<argument>Portal42</argument><argument>alice</argument><argument>LDAP</argument>" +
				"<argument>vsys1</argument><argument>Domain42</argument>" +
				strings.Repeat("<argument/>", 4) + "<argument>tunnel</argument><argument>-1</argument>" +
				"<argument>4100</argument><argument>192.0.2.48</argument></application-desc></jnlp>"
		case 3:
			if r.URL.Path != "/ssl-vpn/getconfig.esp" {
				t.Errorf("getconfig path=%s", r.URL.Path)
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			for key, want := range map[string]string{
				"user": "alice", "portal": "Portal42", "domain": "Domain42",
				"authcookie": "cookie-value", "preferred-ip": "192.0.2.48",
				"enc-algo": "aes-128-cbc,aes-256-cbc", "hmac-algo": "sha256,sha1",
			} {
				if got := r.Form.Get(key); got != want {
					t.Errorf("getconfig %s=%q want %q", key, got, want)
				}
			}
			// Real observed fixture format: no status attribute or need-tunnel flag.
			content = "<response><ip-address>192.0.2.48</ip-address><netmask>255.255.255.255</netmask>" +
				"<ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url></response>"
		default:
			t.Errorf("unexpected call %d", calls)
			return nil, errors.New("unexpected call")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(content)), Header: make(http.Header), Request: r}, nil
	})
	ctx := context.Background()
	if err := c.prelogin(ctx); err != nil {
		t.Fatal(err)
	}
	session, err := c.login(ctx, "alice", "pw")
	if err != nil {
		t.Fatal(err)
	}
	cfg, ip, err := c.getConfig(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "192.0.2.48/32" || cfg.TunnelURL != "/ssl-tunnel-connect.sslvpn" || calls != 3 {
		t.Fatalf("config=%+v ip=%s calls=%d", cfg, ip, calls)
	}
}

func TestOpenConnectUnsupportedAuthenticationModes(t *testing.T) {
	cases := []struct{ name, path, body string }{
		{"saml-method-only", "prelogin", "<prelogin-response><status>Success</status><saml-auth-method>REDIRECT</saml-auth-method></prelogin-response>"},
		{"gateway-challenge-xml", "login", "<challenge><respmsg>2FA required</respmsg><inputstr>dead</inputstr></challenge>"},
		{"gateway-challenge-js", "login", `var respStatus = "Challenge"; thisForm.inputStr.value = "dead";`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newControl(Config{Gateway: "vpn.example.com"})
			if err != nil {
				t.Fatal(err)
			}
			defer c.close()
			c.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header), Request: r}, nil
			})
			if tc.path == "prelogin" {
				err = c.prelogin(context.Background())
			} else {
				_, err = c.login(context.Background(), "alice", "password")
			}
			if !errors.Is(err, ErrInteractiveAuth) {
				t.Fatalf("want ErrInteractiveAuth, got %v", err)
			}
		})
	}
}

func TestOpenConnectGatewayExplicitFailure(t *testing.T) {
	for _, body := range []string{
		`<response status="error"><error>bad cookie</error><ip-address>192.0.2.48</ip-address></response>`,
		`<response><need-tunnel>no</need-tunnel><ip-address>192.0.2.48</ip-address></response>`,
		`<response><ssl-tunnel-url>https://evil.test/redirect</ssl-tunnel-url><ip-address>192.0.2.48</ip-address></response>`,
	} {
		t.Run(body, func(t *testing.T) {
			c, err := newControl(Config{Gateway: "vpn.example.com"})
			if err != nil {
				t.Fatal(err)
			}
			defer c.close()
			c.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
			})
			if _, _, err := c.getConfig(context.Background(), session{User: "alice", Cookie: "cookie-value"}); err == nil {
				t.Fatal("accepted rejected or unsafe gateway config")
			}
		})
	}
}
