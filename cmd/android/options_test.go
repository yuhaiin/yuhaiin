package yuhaiin

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type countingUIDDumper struct {
	lookups atomic.Int32
	fail    atomic.Bool
}

func (*countingUIDDumper) DumpUid(int32, string, int32, string, int32) (int32, error) {
	return 10001, nil
}
func (d *countingUIDDumper) GetUidInfo(int32) (string, error) {
	d.lookups.Add(1)
	if d.fail.Load() {
		return "", errors.New("lookup failed")
	}
	return strings.Clone("example.android.app"), nil
}

func TestProcessNameUsesUIDCache(t *testing.T) {
	d := &countingUIDDumper{}
	p := NewUidDumper(d)
	for range 3 {
		info, err := p.ProcessName("tcp", netapi.EmptyAddr, netapi.EmptyAddr)
		if err != nil || info.Path != "example.android.app" || info.Uid != 10001 {
			t.Fatalf("process: %+v %v", info, err)
		}
	}
	if got := d.lookups.Load(); got != 1 {
		t.Fatalf("UID info callback called %d times, want 1", got)
	}
}

func TestUIDCacheRetriesFailureAndCoalescesConcurrentLookups(t *testing.T) {
	d := &countingUIDDumper{}
	p := NewUidDumper(d)
	d.fail.Store(true)
	if _, err := p.ProcessName("tcp", netapi.EmptyAddr, netapi.EmptyAddr); err == nil {
		t.Fatal("missing lookup error")
	}
	d.fail.Store(false)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := p.ProcessName("udp", netapi.EmptyAddr, netapi.EmptyAddr); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := d.lookups.Load(); got != 2 {
		t.Fatalf("UID callbacks = %d, want failed lookup + one successful lookup", got)
	}
}

func BenchmarkProcessNameUIDCache(b *testing.B) {
	d := &countingUIDDumper{}
	p := NewUidDumper(d)
	if _, err := p.ProcessName("tcp", netapi.EmptyAddr, netapi.EmptyAddr); err != nil {
		b.Fatal(err)
	}
	before := d.lookups.Load()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := p.ProcessName("tcp", netapi.EmptyAddr, netapi.EmptyAddr); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(d.lookups.Load()-before)/float64(b.N), "UID-calls/op")
}
