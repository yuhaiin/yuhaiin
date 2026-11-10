package yuhaiin

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

type fakeActions struct {
	restored  string
	restarts  int
	withdrawn bool
	updates   []string
}

func (f *fakeActions) RestoreConfig(path string) error {
	data, err := os.ReadFile(path)
	f.restored = string(data)
	_ = os.Remove(path)
	return err
}
func (f *fakeActions) RestartCore() error   { f.restarts++; return nil }
func (f *fakeActions) PrivacyState() string { return `{"consents":{"vpn":true}}` }
func (f *fakeActions) WithdrawConsent() error {
	f.withdrawn = true
	return nil
}
func (f *fakeActions) UpdateState() string { return `{"stage":"IDLE"}` }
func (f *fakeActions) UpdateAction(action, arg string) error {
	f.updates = append(f.updates, action+":"+arg)
	return nil
}
func (f *fakeActions) AppInfo() string { return `{"versionName":"v2-test"}` }

func withActions(t *testing.T) *fakeActions {
	a := &fakeActions{}
	SetPlatformActions(a)
	t.Cleanup(func() { SetPlatformActions(nil) })
	return a
}

func authed(method, path, body string) req {
	return req{method: method, path: path, body: body, cookie: testToken, header: method != "GET", json: method != "GET"}
}

func TestRouteProfilesCRUD(t *testing.T) {
	h := newTestPlatformAPI(t)
	code, body := authed("GET", "/android/v1/routes", "").do(t, h)
	if code != 200 || !strings.Contains(body, `"preset":true`) || !strings.Contains(body, AdvRouteAll) {
		t.Fatalf("%d %s", code, body)
	}
	for _, bad := range []string{`{"name":""}`, `{"name":"a b"}`, `{"name":"x/y"}`} {
		if code, _ := authed("POST", "/android/v1/routes", bad).do(t, h); code != 400 {
			t.Fatalf("%s accepted", bad)
		}
	}
	if code, body := authed("POST", "/android/v1/routes", `{"name":"work"}`).do(t, h); code != 200 {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := authed("POST", "/android/v1/routes", `{"name":"work"}`).do(t, h); code != 409 {
		t.Fatal("duplicate accepted")
	}
	if code, body := authed("PUT", "/android/v1/routes", `{"name":"work","content":"10.0.0.0/8\nnot-a-cidr"}`).do(t, h); code != 400 || !strings.Contains(body, "line 2") {
		t.Fatalf("invalid content: %d %s", code, body)
	}
	if code, _ := authed("PUT", "/android/v1/routes", `{"name":"work","content":"10.0.0.0/8\n2001:db8::/32\n1.1.1.1"}`).do(t, h); code != 200 {
		t.Fatal("valid content rejected")
	}
	if got := GetStore().GetString(routeContentKey + "work"); got != "10.0.0.0/8\n2001:db8::/32\n1.1.1.1" {
		t.Fatalf("content = %q", got)
	}
	GetStore().PutString(AdvRouteKey, "work")
	if code, _ := authed("POST", "/android/v1/routes/delete", `{"name":"`+AdvRouteAll+`"}`).do(t, h); code != 400 {
		t.Fatal("preset deleted")
	}
	if code, _ := authed("POST", "/android/v1/routes/delete", `{"name":"work"}`).do(t, h); code != 200 {
		t.Fatal("delete failed")
	}
	if GetStore().GetString(AdvRouteKey) != AdvRouteAll || strings.Contains(GetStore().GetString(savedRoutesKey), "work") {
		t.Fatal("deleting the active profile must fall back to the default")
	}
}

func TestLogsAndOneTimeDownload(t *testing.T) {
	h := newTestPlatformAPI(t)
	old := readLogcat
	readLogcat = func(context.Context, int) ([]byte, error) { return []byte("I yuhaiin: hello\n"), nil }
	t.Cleanup(func() { readLogcat = old })
	if code, body := authed("GET", "/android/v1/logs?lines=5", "").do(t, h); code != 200 || body != "I yuhaiin: hello\n" {
		t.Fatalf("%d %q", code, body)
	}
	code, body := authed("POST", "/android/v1/logs/export", "{}").do(t, h)
	var link struct {
		URL  string `json:"url"`
		Name string `json:"name"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &link) != nil || !strings.HasPrefix(link.URL, "/android/v1/download/") {
		t.Fatalf("%d %s", code, body)
	}
	// LAN peers cannot fetch it, even with the link.
	if code, _ := (req{method: "GET", path: link.URL, remote: "192.168.1.9:1"}).do(t, h); code != 403 {
		t.Fatal("LAN download allowed")
	}
	// WebView probes the link, then the cookie-less DownloadManager fetches it;
	// the link stops working after a few fetches.
	for range downloadMaxUses {
		if code, body := (req{method: "GET", path: link.URL}).do(t, h); code != 200 || body != "I yuhaiin: hello\n" {
			t.Fatalf("download: %d %q", code, body)
		}
	}
	if code, _ := (req{method: "GET", path: link.URL}).do(t, h); code != 404 {
		t.Fatal("download link reused beyond its limit")
	}
	if code, _ := (req{method: "GET", path: "/android/v1/download/guess"}).do(t, h); code != 404 {
		t.Fatal("unknown token served")
	}
	// Creating links still requires the session.
	if code, _ := (req{method: "POST", path: "/android/v1/logs/export", body: "{}", header: true, json: true}).do(t, h); code != http.StatusUnauthorized {
		t.Fatal("export without session")
	}
}

func TestBackupPreviewRejectsInvalidData(t *testing.T) {
	h := newTestPlatformAPI(t)
	for _, bad := range []string{`{}`, `{"format":"other","version":1}`, `not json`} {
		if code, _ := authed("POST", "/android/v1/backup/preview", bad).do(t, h); code != 400 {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestBackupPreviewAcceptsEveryCoreBackupVersion(t *testing.T) {
	for version, ok := range map[int]bool{1: true, 2: true, 3: false} {
		_, err := previewOf(fmt.Appendf(nil, `{"format":"yuhaiin-config","version":%d,"createdAt":"x","tables":{"nodes_v2":{"rows":[[1]]}}}`, version))
		if (err == nil) != ok {
			t.Fatalf("version %d: %v", version, err)
		}
	}
}

func TestBackupExportRestoreRoundTrip(t *testing.T) {
	h := newTestPlatformAPI(t)
	a := withActions(t)
	code, body := authed("POST", "/android/v1/backup/export", "{}").do(t, h)
	var link struct {
		URL string `json:"url"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &link) != nil {
		t.Fatalf("%d %s", code, body)
	}
	_, backup := (req{method: "GET", path: link.URL}).do(t, h)
	if code, body := authed("POST", "/android/v1/backup/preview", backup).do(t, h); code != 200 || !strings.Contains(body, "createdAt") {
		t.Fatalf("preview: %d %s", code, body)
	}
	if code, body := authed("POST", "/android/v1/backup/restore", backup).do(t, h); code != 202 {
		t.Fatalf("restore: %d %s", code, body)
	}
	if a.restored != backup {
		t.Fatal("restore did not hand the validated backup to Android")
	}
}

func TestPlatformActionsPassThrough(t *testing.T) {
	h := newTestPlatformAPI(t)
	if code, _ := authed("GET", "/android/v1/privacy", "").do(t, h); code != 503 {
		t.Fatal("missing actions must be reported")
	}
	a := withActions(t)
	if code, body := authed("GET", "/android/v1/privacy", "").do(t, h); code != 200 || !strings.Contains(body, `"vpn":true`) {
		t.Fatalf("%d %s", code, body)
	}
	if code, _ := authed("POST", "/android/v1/privacy/withdraw", "{}").do(t, h); code != 200 || !a.withdrawn {
		t.Fatal("withdraw")
	}
	if code, _ := authed("POST", "/android/v1/update", `{"action":"install-anything"}`).do(t, h); code != 400 {
		t.Fatal("unknown update action accepted")
	}
	if code, _ := authed("POST", "/android/v1/update", `{"action":"channel","channel":"nightly"}`).do(t, h); code != 400 {
		t.Fatal("unknown channel accepted")
	}
	if code, _ := authed("POST", "/android/v1/update", `{"action":"channel","channel":"beta"}`).do(t, h); code != 200 || a.updates[0] != "channel:beta" {
		t.Fatalf("update: %v", a.updates)
	}
	if code, _ := authed("POST", "/android/v1/core/restart", "{}").do(t, h); code != 202 || a.restarts != 1 {
		t.Fatal("restart")
	}
	if code, body := authed("GET", "/android/v1/app", "").do(t, h); code != 200 || !strings.Contains(body, "v2-test") {
		t.Fatalf("app: %s", body)
	}
}

func TestPlatformSettingsPortAndRestartFlags(t *testing.T) {
	h := newTestPlatformAPI(t)
	put := func(body string) (int, string) { return authed("PUT", "/android/v1/settings", body).do(t, h) }
	if code, _ := put(`{"httpProxyPort":70000}`); code != 400 {
		t.Fatal("invalid port accepted")
	}
	code, body := put(`{"httpProxyPort":8188,"allowLan":true,"processLookupMode":"off"}`)
	if code != 200 || GetStore().GetInt(NewHTTPPortKey) != 8188 || !GetStore().GetBoolean(AllowLanKey) {
		t.Fatalf("%d %s", code, body)
	}
	if !strings.Contains(body, `"restartRequired":["allowLan"]`) {
		t.Fatalf("restart flags missing: %s", body)
	}
}
