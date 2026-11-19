package protection

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
)

type fakeBackend struct {
	mu        sync.Mutex
	desired   sysnet.ProtectionSettings
	effective bool
	updates   []Policy
	enables   int
	disables  int
	failNext  error
	statusErr error
	session   uint64
	blocked   uint64
	closed    bool
}

func (f *fakeBackend) Status(context.Context) (sysnet.ProtectionStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return sysnet.ProtectionStatus{}, f.statusErr
	}
	st := UnsupportedStatus()
	st.Supported, st.Desired, st.Effective = true, f.desired, f.effective
	st.State = sysnet.ProtectionDisabled
	if f.effective {
		st.State = sysnet.ProtectionProtected
		st.Blocked = &sysnet.ProtectionCounters{Packets: f.blocked}
	}
	return st, nil
}
func (f *fakeBackend) Enable(_ context.Context, p Policy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	f.enables++
	f.desired = sysnet.ProtectionSettings{Enabled: true, StartAtBoot: p.StartAtBoot}
	f.effective = true
	f.updates = append(f.updates, p)
	return nil
}
func (f *fakeBackend) Update(_ context.Context, p Policy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	f.updates = append(f.updates, p)
	return nil
}
func (f *fakeBackend) Disable(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disables++
	f.desired.Enabled, f.effective = false, false
	return nil
}
func (f *fakeBackend) Close() error    { f.mu.Lock(); f.closed = true; f.mu.Unlock(); return nil }
func (f *fakeBackend) Session() uint64 { f.mu.Lock(); defer f.mu.Unlock(); return f.session }
func (f *fakeBackend) count() int      { f.mu.Lock(); defer f.mu.Unlock(); return len(f.updates) }
func (f *fakeBackend) last() Policy    { f.mu.Lock(); defer f.mu.Unlock(); return f.updates[len(f.updates)-1] }

func TestControllerSyncsOnlyChanges(t *testing.T) {
	b := &fakeBackend{}
	c := newController(b, time.Hour)
	ctx := context.Background()
	c.SetInputs(Inputs{Tunnels: []Tunnel{{Name: "utun4", IPv4: true}}})
	// Disabled: nothing is sent.
	c.sync("test")
	if b.count() != 0 {
		t.Fatal("policy sent while disabled")
	}
	st, err := c.Save(ctx, sysnet.ProtectionSettings{Enabled: true, StartAtBoot: true})
	if err != nil || st.State != sysnet.ProtectionProtected || b.enables != 1 {
		t.Fatalf("save: %+v %v", st, err)
	}
	p := b.last()
	if p.Mode != sysnet.ProtectionModeStandard || !p.StartAtBoot || len(p.PrivateNetworks) == 0 || len(p.Tunnels) != 1 {
		t.Fatalf("policy = %+v", p)
	}
	// Same inputs: no update.
	c.sync("test")
	if b.count() != 1 {
		t.Fatal("unchanged policy sent again")
	}
	// Changed inputs: one update with the latest state.
	c.SetInputs(Inputs{Bypass: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, Tunnels: []Tunnel{{Name: "utun4", IPv4: true}}})
	c.SetInputs(Inputs{Bypass: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, Tunnels: []Tunnel{{Name: "utun4", IPv4: true}}})
	c.sync("test")
	if b.count() != 2 || b.last().BypassNetworks[0] != netip.MustParsePrefix("198.51.100.0/24") {
		t.Fatalf("updates = %+v", b.updates)
	}
	// The backend lost the runtime part (reconnected): send again.
	b.mu.Lock()
	b.session++
	b.mu.Unlock()
	c.sync("test")
	if b.count() != 3 {
		t.Fatal("not resent after a new session")
	}
}

func TestControllerReportsFailures(t *testing.T) {
	b := &fakeBackend{}
	c := newController(b, time.Hour)
	ctx := context.Background()
	c.SetInputs(Inputs{Tunnels: []Tunnel{{Name: "utun4"}}, Ignored: []string{"rule x ignored"}})
	if _, err := c.Save(ctx, sysnet.ProtectionSettings{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	b.failNext = errors.New("pf rejected the rules")
	c.SetInputs(Inputs{Tunnels: []Tunnel{{Name: "utun5"}}})
	c.sync("test")
	st := c.Status(ctx)
	if st.State != sysnet.ProtectionDegraded || !has(st, sysnet.ProblemPolicySync) {
		t.Fatalf("status = %+v", st)
	}
	// The failed update is retried on the next sync.
	c.sync("test")
	if b.last().Tunnels[0].Name != "utun5" || c.Status(ctx).State != sysnet.ProtectionProtected {
		t.Fatal("not retried")
	}
	// No running TUN: protection blocks everything, and says so.
	c.SetInputs(Inputs{})
	c.sync("test")
	if st := c.Status(ctx); !has(st, sysnet.ProblemTunnelMissing) {
		t.Fatalf("status = %+v", st)
	}
	// The service cannot be reached: never reported as protected.
	b.mu.Lock()
	b.statusErr = Problem(sysnet.ProblemServiceDown, "not reachable", "")
	b.mu.Unlock()
	if st := c.Status(ctx); st.State != sysnet.ProtectionError || st.Effective || st.Service != "unreachable" {
		t.Fatalf("status = %+v", st)
	}
	if _, err := c.Save(ctx, sysnet.ProtectionSettings{Enabled: false}); err == nil {
		t.Fatal("disable without the service reported success")
	}
}

func TestControllerBlockedTimestampAndClose(t *testing.T) {
	b := &fakeBackend{}
	c := newController(b, time.Hour)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	ctx := context.Background()
	_, _ = c.Save(ctx, sysnet.ProtectionSettings{Enabled: true})
	if st := c.Status(ctx); st.Blocked == nil || st.Blocked.LastAt != nil {
		t.Fatalf("blocked = %+v", st.Blocked)
	}
	b.mu.Lock()
	b.blocked = 5
	b.mu.Unlock()
	now = time.Unix(2000, 0)
	if st := c.Status(ctx); st.Blocked.LastAt == nil || *st.Blocked.LastAt != 2000 {
		t.Fatalf("blocked = %+v", st.Blocked)
	}
	c.start()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if b.disables != 0 || !b.closed {
		t.Fatal("closing the controller must not disable protection")
	}
}

func TestDisableAndUnsupported(t *testing.T) {
	b := &fakeBackend{}
	c := newController(b, time.Hour)
	ctx := context.Background()
	_, _ = c.Save(ctx, sysnet.ProtectionSettings{Enabled: true})
	if st, err := c.Save(ctx, sysnet.ProtectionSettings{Enabled: false}); err != nil || st.State != sysnet.ProtectionDisabled {
		t.Fatal(st, err)
	}
	u := newController(Unsupported{}, time.Hour)
	if st := u.Status(ctx); st.State != sysnet.ProtectionUnsupported || st.Supported {
		t.Fatalf("status = %+v", st)
	}
	if _, err := u.Save(ctx, sysnet.ProtectionSettings{Enabled: true}); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func has(st sysnet.ProtectionStatus, code string) bool {
	for _, p := range st.Problems {
		if p.Code == code {
			return true
		}
	}
	return false
}

func TestPolicyValidationAndFingerprint(t *testing.T) {
	p := Policy{Mode: sysnet.ProtectionModeStandard, BypassNetworks: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("198.51.100.0/24")},
		Tunnels: []Tunnel{{Name: "utun5"}, {Name: "utun4"}}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	q := p
	q.BypassNetworks = []netip.Prefix{p.BypassNetworks[1], p.BypassNetworks[0], p.BypassNetworks[1]}
	q.Tunnels = []Tunnel{{Name: "utun4"}, {Name: "utun5"}}
	if p.Fingerprint() != q.Fingerprint() {
		t.Fatal("order or duplicates change the fingerprint")
	}
	if d := Diff(p, Policy{Mode: p.Mode}); len(d) != 2 {
		t.Fatalf("diff = %v", d)
	}
	if per := p.Persistent(); per.Tunnels != nil || per.OwnTraffic {
		t.Fatal("persistent part keeps runtime fields")
	}
	// Zones and invalid prefixes never pass the wire format.
	var bad Policy
	if err := json.Unmarshal([]byte(`{"mode":"standard","privateNetworks":["fe80::1%en0/128"],"bypassNetworks":[]}`), &bad); err == nil {
		t.Fatal("zoned prefix decoded")
	}
	if err := json.Unmarshal([]byte(`{"mode":"standard","privateNetworks":["10.0.0.0/33"],"bypassNetworks":[]}`), &bad); err == nil {
		t.Fatal("invalid prefix decoded")
	}
	for _, name := range []string{"", "1abc", "a b", "averyveryverylongname"} {
		if ValidInterfaceName(name) == nil {
			t.Errorf("%q accepted", name)
		}
	}
}
