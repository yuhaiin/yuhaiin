package main

import (
	"bytes"
	"errors"
	core "github.com/Asutorufa/yuhaiin/cmd/android"
	"strings"
	"sync/atomic"
	"testing"
)

func TestUnknownOperation(t *testing.T) {
	out, st := call("nope.nothing", nil)
	if st != statusUnknownOp || !strings.Contains(string(out), "nope.nothing") {
		t.Fatalf("got %d %q", st, out)
	}
}

func TestBadRequest(t *testing.T) {
	_, st := call("store.get", []byte("{not json"))
	if st != statusBadRequest {
		t.Fatalf("status %d", st)
	}
	_, st = call("store.get", []byte(`{"keys":[{"key":"a","type":"weird"}]}`))
	if st != statusBadRequest {
		t.Fatalf("unknown type status %d", st)
	}
	_, st = call("core.init", []byte(`{}`))
	if st != statusBadRequest {
		t.Fatalf("empty savePath status %d", st)
	}
}

func TestPanicIsRecovered(t *testing.T) {
	operations["test.panic"] = func([]byte) ([]byte, error) { panic("boom") }
	defer delete(operations, "test.panic")
	out, st := call("test.panic", nil)
	if st != statusPanic || !strings.Contains(string(out), "boom") {
		t.Fatalf("got %d %q", st, out)
	}
}

func TestErrorStatus(t *testing.T) {
	operations["test.err"] = func([]byte) ([]byte, error) { return nil, errors.New("consent_required: x") }
	defer delete(operations, "test.err")
	out, st := call("test.err", nil)
	if st != statusErr || string(out) != "consent_required: x" {
		t.Fatalf("got %d %q", st, out)
	}
	operations["test.nohost"] = func([]byte) ([]byte, error) { return nil, errNoHost }
	defer delete(operations, "test.nohost")
	if _, st := call("test.nohost", nil); st != statusNoHost {
		t.Fatalf("status %d", st)
	}
}

func TestParseCIDR(t *testing.T) {
	out, st := call("net.parse_cidr", []byte(`{"cidrs":["10.1.2.3/8","::/0"]}`))
	if st != statusOK {
		t.Fatalf("%d %s", st, out)
	}
	if got := string(out); got != `{"prefixes":[{"ip":"10.0.0.0","mask":8},{"ip":"::","mask":0}]}` {
		t.Fatal(got)
	}
	if _, st := call("net.parse_cidr", []byte(`{"cidrs":["bogus"]}`)); st != statusErr {
		t.Fatalf("invalid cidr status %d", st)
	}
}

func TestSessionWhenStopped(t *testing.T) {
	out, st := call("core.session", nil)
	if st != statusOK || string(out) != `{"port":0,"running":false,"token":""}` {
		t.Fatalf("%d %s", st, out)
	}
}

func TestMissingHost(t *testing.T) {
	installHost(nil)
	if _, err := hostCall("x", nil); !errors.Is(err, errNoHost) {
		t.Fatal(err)
	}
}

type fakeHost struct {
	protected atomic.Int32
	calls     []string
	resp      []byte
	err       error
}

func (f *fakeHost) Protect(fd int32) bool                                      { f.protected.Add(1); return true }
func (f *fakeHost) Bind(fd int32, iface string) int64                          { return 7 }
func (f *fakeHost) DumpUID(int32, string, int32, string, int32) (int32, error) { return 10001, nil }
func (f *fakeHost) Establish(g int64, c string) (int32, error)                 { return 42, nil }
func (f *fakeHost) Call(op string, req []byte) ([]byte, error) {
	f.calls = append(f.calls, op+":"+string(req))
	return f.resp, f.err
}

func TestCallbacksIgnoredWhenCoreStopped(t *testing.T) {
	h := &fakeHost{}
	installHost(h)
	defer installHost(nil)

	coreActive.Store(false)
	if !(sockets{}).Protect(5) || h.protected.Load() != 0 {
		t.Fatal("stopped core must not reach the host")
	}
	if (sockets{}).Bind(5, "wlan0") != 0 {
		t.Fatal("stopped core must not bind")
	}
	if _, err := (vpnProvider{}).Establish(1, "{}"); err == nil {
		t.Fatal("stopped core must not establish a VPN")
	}
	(vpnProvider{}).StatusChanged(`{"state":"x"}`)
	if len(h.calls) != 0 {
		t.Fatalf("unexpected host calls %v", h.calls)
	}
	// Releasing descriptors must always get through.
	(vpnProvider{}).Release(3)
	if len(h.calls) != 1 || h.calls[0] != `vpn.release:{"generation":3}` {
		t.Fatalf("release calls %v", h.calls)
	}

	coreActive.Store(true)
	defer coreActive.Store(false)
	if !(sockets{}).Protect(5) || h.protected.Load() != 1 {
		t.Fatal("active core must reach the host")
	}
	if (sockets{}).Bind(5, "") != 7 {
		t.Fatal("bind")
	}
	if fd, err := (vpnProvider{}).Establish(1, "{}"); err != nil || fd != 42 {
		t.Fatal(fd, err)
	}
}

func TestInterfacesAdapter(t *testing.T) {
	h := &fakeHost{resp: []byte(`[{"name":"wlan0","index":3,"mtu":1500,"isUp":true,"hardwareAddr":"AQID","addresses":[{"address":"192.168.1.2","mask":24}]}]`)}
	installHost(h)
	defer installHost(nil)
	it, err := (interfaces{}).GetInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	i := it.Next()
	if i == nil || i.Name != "wlan0" || i.Index != 3 || !i.IsUp || !bytes.Equal(i.HardwareAddr, []byte{1, 2, 3}) {
		t.Fatalf("%+v", i)
	}
	a := i.Address.Next()
	if a == nil || a.Address != "192.168.1.2" || a.Mask != 24 || i.Address.HasNext() || it.HasNext() {
		t.Fatalf("%+v", a)
	}
}

func TestAppCatalogPassesErrors(t *testing.T) {
	installHost(&fakeHost{err: errors.New("consent_required: no")})
	defer installHost(nil)
	if _, err := (appCatalog{}).InstalledApps(); err == nil || !strings.HasPrefix(err.Error(), "consent_required") {
		t.Fatal(err)
	}
}

// yuhaiin-android mirrors these identifiers in Constants.kt. Changing one here
// is a compatibility change for the app.
func TestMirroredAppIdentifiers(t *testing.T) {
	if core.PlatformCookieName != "yuhaiin_android_platform" {
		t.Fatal("PlatformCookieName changed")
	}
	if core.CoreBackgroundPolicyKey != "core_background_policy" {
		t.Fatal("CoreBackgroundPolicyKey changed")
	}
}
