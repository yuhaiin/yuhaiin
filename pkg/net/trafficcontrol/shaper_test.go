package trafficcontrol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestLimiterValidatesAndDefaults(t *testing.T) {
	for _, r := range []Rate{{BytesPerSecond: -1}, {BytesPerSecond: 1 << 41}, {BytesPerSecond: 0, BurstBytes: 1}, {BytesPerSecond: 100, BurstBytes: -1}} {
		if _, err := NewLimiter(r.BytesPerSecond, r.BurstBytes); !errors.Is(err, ErrInvalidRate) {
			t.Fatalf("accepted invalid limiter %+v: %v", r, err)
		}
	}
	l, err := NewLimiter(2048, 0)
	if err != nil || l == nil || l.burst != 64<<10 {
		t.Fatalf("default burst failed: %#v %v", l, err)
	}
	u, err := NewLimiter(0, 0)
	if err != nil || u != nil {
		t.Fatal("unlimited limiter")
	}
}

func TestHierarchicalDatagramCapsAreAtomic(t *testing.T) {
	m := NewManager()
	c := Config{Enabled: true, Global: Profile{Upload: Rate{BytesPerSecond: 1, BurstBytes: 2}},
		Profiles:        map[string]Profile{"small": {Upload: Rate{BytesPerSecond: 1, BurstBytes: 1}}},
		InboundProfiles: map[string]string{"noisy": "small"}}
	if err := m.Apply(c); err != nil {
		t.Fatal(err)
	}
	noisy := m.Resolve("noisy", "")
	quiet := m.Resolve("quiet", "")
	if !noisy.AllowDatagram(Upload, 1) {
		t.Fatal("first byte")
	}
	for range 100 {
		if noisy.AllowDatagram(Upload, 2) {
			t.Fatal("child burst bypass")
		}
	}
	if !quiet.AllowDatagram(Upload, 1) {
		t.Fatal("rejected child starved parent")
	}
	if quiet.AllowDatagram(Upload, 1) {
		t.Fatal("global burst bypass")
	}
	if !quiet.AllowDatagram(Download, 1024) {
		t.Fatal("download must remain unlimited")
	}
}

func TestProfilesRoutePrecedenceAndSnapshotValidation(t *testing.T) {
	m := NewManager()
	c := Config{Enabled: true,
		Global:         Profile{Upload: Rate{BytesPerSecond: 10, BurstBytes: 10}},
		DefaultProfile: "default",
		Profiles: map[string]Profile{
			"default":    {Download: Rate{BytesPerSecond: 1, BurstBytes: 1}},
			"restricted": {Upload: Rate{BytesPerSecond: 1, BurstBytes: 1}},
		},
		InboundProfiles: map[string]string{"a": "restricted"},
		RouteProfiles:   map[string]string{"r1": "restricted"},
	}
	if err := m.Apply(c); err != nil {
		t.Fatal(err)
	}
	if !m.Resolve("other", "").Enabled(Download) || m.Resolve("a", "").Enabled(Download) {
		t.Fatal("fallback incorrectly applied to bound route")
	}
	if !m.Resolve("a", "r1").Enabled(Upload) {
		t.Fatal("bound limit missing")
	}
	c.InboundProfiles["bad"] = "absent"
	if err := m.Apply(c); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if got := m.Config(); got.InboundProfiles["a"] != "restricted" {
		t.Fatalf("partial publication: %+v", got)
	}
	got := m.Config()
	got.Profiles["restricted"] = Profile{}
	got.InboundProfiles["a"] = "other"
	if m.Config().InboundProfiles["a"] != "restricted" {
		t.Fatal("mutable external map modified published policy")
	}
	if err := m.Apply(Config{}); err != nil {
		t.Fatal(err)
	}
	if m.Resolve("a", "r1").Enabled(Upload) {
		t.Fatal("disabled policy still applied")
	}
}

func TestShapedWriterPacingAndCancel(t *testing.T) {
	m := NewManager()
	if err := m.Apply(Config{Enabled: true, Global: Profile{Upload: Rate{BytesPerSecond: 100000, BurstBytes: 8}}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var buf bytes.Buffer
	w := ShapedWriter{Writer: &buf, Context: ctx, Policy: m.Resolve("", ""), Direction: Upload}
	content := bytes.Repeat([]byte{0x42}, 64)
	n, err := w.Write(content)
	if err != nil || n != len(content) || !bytes.Equal(buf.Bytes(), content) {
		t.Fatalf("writer result=%d err=%v len=%d", n, err, buf.Len())
	}
	one := NewManager()
	if err := one.Apply(Config{Enabled: true, Global: Profile{Upload: Rate{BytesPerSecond: 1, BurstBytes: 1}}}); err != nil {
		t.Fatal(err)
	}
	stop, abort := context.WithCancel(t.Context())
	abort()
	n, err = ShapedWriter{Writer: io.Discard, Context: stop, Policy: one.Resolve("", ""), Direction: Upload}.Write(content)
	if n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled write progressed=%d err=%v", n, err)
	}
}

type shortWrite struct{}

func (shortWrite) Write([]byte) (int, error) { return 1, io.ErrShortWrite }

func TestShapedWriterRefundsUnwrittenReservation(t *testing.T) {
	limiter, err := NewLimiter(1, 16)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{up: [3]*Limiter{limiter}}
	n, err := (ShapedWriter{Writer: shortWrite{}, Context: t.Context(), Policy: policy, Direction: Upload}).Write(make([]byte, 16))
	if n != 1 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("write result=%d err=%v", n, err)
	}
	limiter.mu.Lock()
	next := limiter.next
	limiter.mu.Unlock()
	if !next.Before(time.Now().Add(-14 * time.Second)) {
		t.Fatalf("unused reservation still consumes quota: next=%v", next)
	}
}

func TestSnapshotAtomicConcurrentActivation(t *testing.T) {
	m := NewManager()
	a := Config{Enabled: true, Global: Profile{Upload: Rate{BytesPerSecond: 1000000}}}
	b := Config{Enabled: true, Global: Profile{Download: Rate{BytesPerSecond: 2000000}}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 400 {
				_ = m.Resolve("a", "route").Enabled(Upload)
				_ = m.Resolve("a", "route").Enabled(Download)
			}
		})
	}
	for range 100 {
		if err := m.Apply(a); err != nil {
			t.Fatal(err)
		}
		if err := m.Apply(b); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func BenchmarkDatagramPolicyUnlimited(b *testing.B) {
	m := NewManager()
	p := m.Resolve("", "")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !p.AllowDatagram(Upload, 1400) {
			b.Fatal("unlimited denied")
		}
	}
}
func BenchmarkPolicyResolve(b *testing.B) {
	m := NewManager()
	if err := m.Apply(Config{Enabled: true, Profiles: map[string]Profile{"normal": {Upload: Rate{BytesPerSecond: 1 << 40, BurstBytes: 1 << 20}}}, InboundProfiles: map[string]string{"mixed": "normal"}}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = m.Resolve("mixed", "")
	}
}

func TestCanceledPacingDoesNotConsumeFutureQuota(t *testing.T) {
	m := NewManager()
	if err := m.Apply(Config{Enabled: true, Global: Profile{Upload: Rate{BytesPerSecond: 1, BurstBytes: 1}}}); err != nil {
		t.Fatal(err)
	}
	p := m.Resolve("", "")
	if !p.AllowDatagram(Upload, 1) {
		t.Fatal("initial burst")
	}
	limiter := p.up[0]
	limiter.mu.Lock()
	before := limiter.next
	limiter.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- p.WaitBytes(ctx, Upload, 1) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wait returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled paced write did not stop")
	}
	limiter.mu.Lock()
	after := limiter.next
	limiter.mu.Unlock()
	if !after.Equal(before) {
		t.Fatalf("cancellation reserved future quota: before=%v after=%v", before, after)
	}
}

func TestPacedStreamWakesOnPolicyChange(t *testing.T) {
	m := NewManager()
	cfg := Config{Enabled: true, Global: Profile{Upload: Rate{BytesPerSecond: 1, BurstBytes: 1}}}
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	p := m.Resolve("", "")
	if !p.AllowDatagram(Upload, 1) {
		t.Fatal("initial byte")
	}
	done := make(chan error, 1)
	go func() { done <- p.WaitBytes(t.Context(), Upload, 1) }()
	cfg.Global.Upload.BytesPerSecond = 1000000
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("paced stream slept against obsolete rate")
	}
}

func TestPolicyAdmissionDuringActivation(t *testing.T) {
	m := NewManager()
	cfg := Config{Enabled: true, Global: Profile{Upload: Rate{BytesPerSecond: 1 << 40, BurstBytes: 1 << 20}},
		Profiles:        map[string]Profile{"shared": {Upload: Rate{BytesPerSecond: 1 << 40, BurstBytes: 1 << 20}}},
		InboundProfiles: map[string]string{"a": "shared"}, RouteProfiles: map[string]string{"r": "shared"}}
	if err := m.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			p := m.Resolve("a", "r")
			for range 1000 {
				p.AllowDatagram(Upload, 100)
				_ = p.WaitBytes(t.Context(), Download, 100)
			}
		})
	}
	for i := range 100 {
		cfg.Global.Upload.BytesPerSecond = (1 << 40) - int64(i)
		cfg.Profiles["shared"] = Profile{Upload: Rate{BytesPerSecond: (1 << 40) - int64(i), BurstBytes: 1 << 20}}
		if err := m.Apply(cfg); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
