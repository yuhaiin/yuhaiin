package yuhaiin

import (
	json "encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/platformvpn"
)

const testToken = "test-platform-token"

func newTestPlatformAPI(t *testing.T) http.Handler {
	t.Helper()
	SetSavePath(t.TempDir())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "management") })
	return newPlatformAPI(&App{}, testToken).wrap(next)
}

type req struct {
	method, path, body, remote, cookie, site string
	header, json                             bool
}

func (r req) do(t *testing.T, h http.Handler) (int, string) {
	t.Helper()
	var body io.Reader
	if r.body != "" {
		body = strings.NewReader(r.body)
	}
	hr := httptest.NewRequest(r.method, "http://127.0.0.1:8080"+r.path, body)
	hr.RemoteAddr = r.remote
	if hr.RemoteAddr == "" {
		hr.RemoteAddr = "127.0.0.1:50000"
	}
	if r.cookie != "" {
		hr.AddCookie(&http.Cookie{Name: PlatformCookieName, Value: r.cookie})
	}
	if r.header {
		hr.Header.Set(platformRequestHeader, "1")
	}
	if r.json {
		hr.Header.Set("Content-Type", "application/json")
	}
	if r.site != "" {
		hr.Header.Set("Sec-Fetch-Site", r.site)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, hr)
	return w.Code, w.Body.String()
}

func TestPlatformAPIAuthorization(t *testing.T) {
	h := newTestPlatformAPI(t)
	for name, tc := range map[string]struct {
		r    req
		want int
	}{
		"no cookie":              {req{method: "GET", path: "/android/v1/status"}, http.StatusUnauthorized},
		"wrong cookie":           {req{method: "GET", path: "/android/v1/status", cookie: "guess"}, http.StatusUnauthorized},
		"LAN client with cookie": {req{method: "GET", path: "/android/v1/status", cookie: testToken, remote: "192.168.1.20:4000"}, http.StatusForbidden},
		"LAN IPv6 client":        {req{method: "GET", path: "/android/v1/status", cookie: testToken, remote: "[fe80::1]:4000"}, http.StatusForbidden},
		"cross-site page":        {req{method: "GET", path: "/android/v1/status", cookie: testToken, site: "cross-site"}, http.StatusForbidden},
		"post without header":    {req{method: "POST", path: "/android/v1/vpn", cookie: testToken, json: true, body: `{"enabled":false}`}, http.StatusForbidden},
		"post as form":           {req{method: "POST", path: "/android/v1/vpn", cookie: testToken, header: true, body: `{"enabled":false}`}, http.StatusUnsupportedMediaType},
		"authorized status":      {req{method: "GET", path: "/android/v1/status", cookie: testToken}, http.StatusOK},
		"authorized IPv6 lo":     {req{method: "GET", path: "/android/v1/status", cookie: testToken, remote: "[::1]:4000"}, http.StatusOK},
	} {
		t.Run(name, func(t *testing.T) {
			if got, body := tc.r.do(t, h); got != tc.want {
				t.Fatalf("status = %d, want %d: %s", got, tc.want, body)
			}
		})
	}
}

func TestPlatformAPIDoesNotShadowManagement(t *testing.T) {
	h := newTestPlatformAPI(t)
	if code, body := (req{method: "GET", path: "/"}).do(t, h); code != 200 || body != "management" {
		t.Fatalf("got %d %q", code, body)
	}
}

func TestPlatformCapabilitiesArePublicButRevealSessionOnly(t *testing.T) {
	h := newTestPlatformAPI(t)
	var caps platformCapabilities
	code, body := req{method: "GET", path: "/android/v1/capabilities", remote: "192.168.1.20:4000"}.do(t, h)
	if code != 200 || json.Unmarshal([]byte(body), &caps) != nil || caps.Platform != "android" || caps.Session {
		t.Fatalf("LAN capabilities: %d %s", code, body)
	}
	_, body = req{method: "GET", path: "/android/v1/capabilities", cookie: testToken}.do(t, h)
	if json.Unmarshal([]byte(body), &caps) != nil || !caps.Session {
		t.Fatalf("WebView capabilities: %s", body)
	}
}

func TestPlatformEnableVPNRequiresOSAuthorization(t *testing.T) {
	h := newTestPlatformAPI(t)
	for auth, code := range map[string]string{
		`{"prepared":false,"consent":true}`: platformvpn.CodePermissionRequired,
		`{"prepared":true,"consent":false}`: platformvpn.CodeConsentRequired,
	} {
		SetVpnProvider(&recordingVpnProvider{auth: auth})
		status, body := req{method: "POST", path: "/android/v1/vpn", cookie: testToken, header: true, json: true, body: `{"enabled":true}`}.do(t, h)
		if status != http.StatusConflict || !strings.Contains(body, code) {
			t.Fatalf("%s: %d %s", auth, status, body)
		}
	}
	SetVpnProvider(nil)
	status, _ := req{method: "POST", path: "/android/v1/vpn", cookie: testToken, header: true, json: true, body: `{"enabled":true}`}.do(t, h)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("no provider: %d", status)
	}
}

func TestPlatformSettingsValidateAndPersist(t *testing.T) {
	h := newTestPlatformAPI(t)
	put := func(body string) (int, string) {
		return req{method: "PUT", path: "/android/v1/settings", cookie: testToken, header: true, json: true, body: body}.do(t, h)
	}
	for _, bad := range []string{
		`{"unknown":true}`,
		`{"perApp":"yes"}`,
		`{"appList":["not a package"]}`,
		`{"mtuProfile":"1234"}`,
		`{"routeProfile":"Missing"}`,
	} {
		if code, body := put(bad); code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d %s", bad, code, body)
		}
	}
	if GetStore().GetBoolean(AdvPerAppKey) {
		t.Fatal("rejected request partially applied")
	}
	code, body := put(`{"perApp":true,"appBypass":true,"appList":["org.example.b","org.example.a","org.example.a"],"mtuProfile":"1500","routeProfile":"Non-Local IPs"}`)
	if code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	if !GetStore().GetBoolean(AdvPerAppKey) || GetStore().GetString(AdvVPNMTUProfileKey) != "1500" {
		t.Fatal("settings not persisted")
	}
	// The Kotlin store reads string sets as JSON arrays.
	if got := GetStore().GetString(AdvAppListKey); got != `["org.example.a","org.example.b"]` {
		t.Fatalf("app list = %s", got)
	}
	var snapshot settingsResponse
	if err := json.Unmarshal([]byte(body), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Values["trackUnderlyingNetwork"] != true || snapshot.Values["coreBackgroundPolicy"] != "while_needed" {
		t.Fatalf("defaults = %v", snapshot.Values)
	}
}

func TestValidPackageName(t *testing.T) {
	for name, ok := range map[string]bool{
		"io.github.asutorufa.yuhaiin": true, "com.a_b.c1": true,
		"": false, "noDot": false, "a..b": false, "1a.b": false, "a.b-c": false, "a.b c": false,
	} {
		if validPackageName(name) != ok {
			t.Errorf("%q: want %v", name, ok)
		}
	}
}
